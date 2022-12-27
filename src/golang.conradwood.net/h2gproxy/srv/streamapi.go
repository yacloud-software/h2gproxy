package srv

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/dustin/go-humanize"
	h2g "golang.conradwood.net/apis/h2gproxy"
	ic "golang.conradwood.net/apis/rpcinterceptor"
	"golang.conradwood.net/go-easyops/auth"
	"golang.conradwood.net/go-easyops/client"
	"golang.conradwood.net/go-easyops/tokens"
	"golang.conradwood.net/go-easyops/utils"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"strings"
	"sync"
	"time"
)

var (
	debug_stream = flag.Bool("debug_stream", false, "debug streaming proxy")
	always_flush = flag.Bool("always_flush", false, "if true ignore low-latency flag and flush each data piece")
	experimental = flag.Bool("experimental", false, "enable experimental mode")
)

// a backend handler must implement this
type StreamingProxy interface {

	// concrete implementation to connect to a backend
	// the proxy will be called with two streams for upload and download requests
	// the "out" (h2g.ServeRequest) is actually a return value. It will be processed once
	// the first bodydata arrives in out_stream (or it is closed or the function returns). the proxy is supposed to modify it
	// Important: backendstream handler must close(out_stream) when done writing
	BackendStream(ctx context.Context, in *h2g.StreamRequest, out_stream chan *h2g.BodyData) error
}

type StreamProxy struct {
	f         *FProxy
	p         StreamingProxy // the backend wrapper
	write_err error          // nil or an error if we failed to write to browser
}

func NewStreamProxy(f *FProxy, sp StreamingProxy) *StreamProxy {
	res := &StreamProxy{f: f, p: sp}
	return res
}

// we forward via grpc...
func (g *StreamProxy) Proxy() {
	t_total := g.f.AddTiming("stream_total")
	defer t_total.Done()
	if rc == nil {
		rc = ic.NewRPCInterceptorServiceClient(client.Connect("rpcinterceptor.RPCInterceptorService"))
	}
	if *printHeaders {
		fmt.Println(headersToString(g.f.req.Header))
	}
	if *debug_stream {
		fmt.Printf("[streamproxy] starting request %s\n", g.f.String())
	}
	g.f.SetHeader("Connection", "close")
	var err error
	t_auth := g.f.AddTiming("stream_auth")
	a := &authResult{}
	a, err = json_auth(g.f) // always check if we got auth stuff
	if g.f.hf.def.NeedAuth && !a.Authenticated() {
		// TODO: depending on the useragent we should do basicauth OR serve the weblogin stuff
		if err != nil {
			fmt.Printf("[streamproxy] Failed to proceed with authentication (error: %s)\n", err)
			return
		}
		if *debug {
			fmt.Printf("[streamproxy] #1 need user but do not have one (==401)\n")
		}
		// if we tried and failed it's forbidden. otherwise send challenge
		if a.GotCredentials() {
			g.f.SetStatus(401) // maybe this should be 401?
			g.f.Write([]byte("403 - access denied"))
			g.f.LogResponse()
			return
		}
		g.f.SetStatus(401)
		g.f.SetHeader("WWW-Authenticate", "Basic realm=\"Login\"")
		g.f.Write([]byte("401 - authentication required"))
		g.f.LogResponse()
		return
	}
	g.f.md = &ic.InMetadata{
		FooBar:       "h2gproxy-streamproxy",
		RequestID:    "", // we want a new one
		UserToken:    "", //do we?
		ServiceToken: tokens.GetServiceTokenParameter(),
	}
	if a != nil && (a.User() != nil) {
		g.f.SetUser(a.SignedUser())

	}
	// safety check: need auth but got no user? - decline
	if g.f.hf.def.NeedAuth && g.f.unsigneduser == nil {
		if *debug {
			fmt.Printf("[streamproxy] #2 need user but do not have one (==401)\n")
		}
		g.f.SetStatus(401)
		g.f.SetHeader("WWW-Authenticate", "Basic realm=\"Login\"")
		g.f.Write([]byte("401 - authentication required"))
		g.f.LogResponse()
		return
	}

	ireq := &ic.InterceptRPCRequest{Service: "h2gproxy",
		Method:     "jsonproxy",
		InMetadata: g.f.md,
	}
	// we need a 'default' context to actually call intercept rpc
	ctx := tokens.ContextWithToken()
	rp, err := rc.InterceptRPC(ctx, ireq)
	if err != nil {
		fmt.Printf("Failed to call intercept rpc: %s\n", utils.ErrorString(err))
		return
	}
	g.f.requestid = rp.RequestID
	late_auth_attempted := false
retry:
	// check for non-verified users
	verify_user(g.f)
	if *debug {
		fmt.Printf("Stream request from %s to %s\n", g.f.PeerIP(), g.f.String())
	}
	t_auth.Done()
	g.f.Started = time.Now()
	/************ now call the backend ****************************/
	nctx, err := g.streamproxy(rp, a)
	g.f.ResponseTime = time.Since(g.f.Started)

	var httpError *HTTPError
	public_error_message := ""
	privileged_error_message := ""

	if err == nil {
		g.f.Flush()
		g.f.LogResponse()
		return
	}

	/******************** the backend return an error ? ******************/
	// very elaborate error handler....

	st := status.Convert(err)
	public_error_message = get_public_error_message(err)
	privileged_error_message = utils.ErrorString(err)
	message := st.Message()
	code := st.Code()
	msg := fmt.Sprintf("[streamproxy] API (type %d) Call (%s), authenticated()=%v, late_auth=%v, failed: code=%d message=%s", g.f.hf.def.Api, g.f.String(), a.Authenticated(), late_auth_attempted, code, message)
	fmt.Println(msg)
	fmt.Printf("[streamproxy] API (type %d) Call (%s) failed: %s\n", g.f.hf.def.Api, g.f.String(), utils.ErrorString(err))
	// sometimes the backend (especially the html backend) may ask us to authenticate a user
	// this happens, if, for example some parts of a backend are accessible by anyone (even non-authenticated people)
	// and some need authentication. we deal with this here.

	// sometimes we actually identified a user (but user is not yet verified)
	if a.User() != nil && !a.User().EmailVerified && a.Authenticated() && !late_auth_attempted {
		late_auth_attempted = true
		g.f.SetUser(a.SignedUser())
		if *debug_rpc {
			fmt.Printf("[grpcprocy] have user %s, but email not verified, thus it was not passed to the backend\n", auth.Description(g.f.unsigneduser))
		}
		nctx, lerr := createContext(g.f, a, rp)
		if lerr != nil {
			g.f.ProcessError(err, 500, "failed to create a user context")
			return
		}
		if g.verifyEmail(nctx) {
			goto retry
		}
		return
	}

	// if we didn't try so before, attempt weblogin
	if code == codes.Unauthenticated && !a.Authenticated() && !late_auth_attempted {
		late_auth_attempted = true
		b := g.late_authenticate()
		if b {
			goto retry
		}
		return
	}

	g.f.customHeaders(&ExtraInfo{Error: err, Message: msg})
	httpError = grpcToHTTP(code)
	httpError.ErrorMessage = public_error_message
	if auth.IsRoot(nctx) {
		httpError.ExtendedErrorString = privileged_error_message
	}

	g.f.SetStatus(httpError.ErrorCode)
	if *debug {
		fmt.Printf("[streamproxy] Returning HTTP error: %d\n", g.f.statusCode)
	}

	resp, lerr := json.Marshal(httpError)
	if lerr != nil {
		fmt.Printf("Failed to marshal http error: %s\n", err)
	}
	g.f.Write(resp)

	g.f.SetAndLogFailure(int32(httpError.ErrorCode), err)
	return
}

/*
**************************************************************
// Wrapper and Buffer around the streaming backend
**************************************************************
*/
func (g *StreamProxy) streamproxy(rp *ic.InterceptRPCResponse, a *authResult) (context.Context, error) {
	// build up the grpc proto
	sv := &h2g.StreamRequest{Port: uint32(g.f.port)}
	sv.Host = strings.ToLower(g.f.req.Host)
	sv.Path = g.f.req.URL.Path
	sv.Method = g.f.req.Method
	if g.f.req.URL != nil {
		sv.Query = g.f.req.URL.RawQuery
	}
	sv.SourceIP = fixIP(g.f.req.RemoteAddr)

	for name, values := range g.f.req.Header {
		if strings.ToLower(name) == "user-agent" && len(values) > 0 {
			sv.UserAgent = values[0]
		}
		h := &h2g.Header{Name: name}
		sv.Headers = append(sv.Headers, h)
		h.Values = values
	}
	err := AddUserHeaders2(g.f, sv)
	if err != nil {
		return nil, err
	}

	// careful here - we do *not* accept multiple values for a given field.
	for name, value := range g.f.RequestValues() {
		p := &h2g.Parameter{Name: name, Value: value}
		sv.Parameters = append(sv.Parameters, p)
	}
	/***************************************************************
	// build a useful context from authresult & intercept response
	***************************************************************/
	t_ctx := g.f.AddTiming("stream_create_context")
	var ctx context.Context
	var cnc context.CancelFunc
	ctx, cnc, err = createCancellableContext(g.f, a, rp)
	t_ctx.Done()
	if err != nil {
		fmt.Printf("[streamproxy] failed to create a new context: %s\n", err)
		return nil, err
	}

	g.f.ctx = ctx
	if *print_rpc {
		for _, h := range sv.Headers {
			fmt.Printf("[streamproxy] request headers: %s=%s\n", h.Name, strings.Join(h.Values, ","))
		}
		for _, h := range sv.Parameters {
			fmt.Printf("[streamproxy] request parameters: %s=%s\n", h.Name, h.Value)
		}
		fmt.Printf("[streamproxy] request path: \"%s\"\n", sv.Path)
		fmt.Printf("[streamproxy] request method: \"%s\"\n", sv.Method)
		fmt.Printf("[streamproxy] request method: \"%s\"\n", sv.Method)
	}
	/***************************************************************
	// make the RPC Call
	***************************************************************/

	// the channel has a large buffer, because we need to decouple the backend speed
	// from the download speed
	// this has the potential for a nasty DoS. We probably need to limit overall ram
	// consumption and start denying clients access if too many buffers are in use
	chan_out := make(chan *h2g.BodyData, 1000000)
	var wg sync.WaitGroup // we have to wait until input and output streams are completed.
	wg.Add(1)
	go g.stream_out(&wg, chan_out) // backend->browser
	started := time.Now()
	err = g.p.BackendStream(ctx, sv, chan_out) // typicalls calls downloadproxy, blocks until stream completed
	elapsed := time.Since(started)
	cnc()
	if *debug_stream {
		fmt.Printf("[streamproxy] BackendStream() returned after %v\n", elapsed)
	}
	if err != nil {
		close(chan_out)
		if *debug_stream {
			fmt.Printf("[streamproxy] returned from BackendStream() with error: %s\n", err)
		}

		wg.Wait()
		return ctx, err

	}
	// no error on backend - wait for streams to complete
	if *debug_stream {
		fmt.Printf("[streamproxy] waiting for backend to complete\n")
	}
	wg.Wait()
	if *debug {
		fmt.Printf("[streamproxy] backend completed\n")
	}
	if g.write_err != nil {
		fmt.Printf("[streamproxy] failed to copy all data to browser: %s\n", g.write_err)
		return ctx, g.write_err
	}
	return ctx, err
}

// called AFTER a backend was called and asked us to authenticate the user
// and we already identified the user, but the users email wasn't verified (yet)
func (g *StreamProxy) verifyEmail(ctx context.Context) bool {
	return g.f.WebVerifyEmail(ctx)
}

// called AFTER a backend was called and asked us to authenticate the user
// depending on the backend it's web or basic or so.
func (g *StreamProxy) late_authenticate() bool {
	if *debug_rpc {
		fmt.Printf("Authentication request from backend detected.\n")
	}
	// depending on the useragent, we serve html or trigger basic-auth
	if g.f.needsBasicAuth() {
		if *debug_rpc {
			fmt.Printf("[streamapi] Cannot do 'late' basic authentication just yet, sorry.")
		}
		g.f.SetHeader("WWW-Authenticate", "Basic realm=\"Login\"")
		g.f.SetStatus(401)
		g.f.Write([]byte("[streamapi] authentication required. you may try passing apikey=XXX as a url parameter or add your credentials to .netrc"))
		return false
	}

	// weblogin
	return g.f.WebLogin()
}

// the backend sent back a streamresponse - send this back to browser
func (sp *StreamProxy) processStreamResponse(resp *h2g.StreamResponse) {
	// process stream response
	mtype := "application/octet-stream"
	if resp.MimeType != "" {
		mtype = resp.MimeType
	}
	sp.f.SetHeader("content-type", mtype)
	//	sp.f.w.Header().Set("content-type", fmt.Sprintf("%s; charset=utf-8", mtype))

	if resp.Filename != "" {
		// chrome seems picky about content-disposition
		/*
			fname := utils.MakeSafeFilename(resp.Filename)
			sp.f.w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fname))
			sp.f.w.Header().Set("X-Content-Type-Options", "nosniff")
			sp.f.w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
		*/

	}

	if resp.Size != 0 {
		sp.f.SetHeader("Content-Length", fmt.Sprintf("%d", resp.Size))
	}
	for k, v := range resp.ExtraHeaders {
		sp.f.SetHeader(k, v)
	}
	code := 200
	if resp.StatusCode != 0 {
		code = int(resp.StatusCode)
	}

	reqid := sp.f.requestid

	if *debug {
		fmt.Printf("Setting requestid header to \"%s\" and code to %d\n", reqid, code)
	}
	sp.f.SetHeader("X-LB-RequestID", reqid)
	sp.f.SetStatus(code)
}

// copy the data from the backend to the browser. send streamresponse before first bodydata
// the backend is expected to write to "out" channel, which this then copies to browser
func (sp *StreamProxy) stream_out(wg *sync.WaitGroup, out chan *h2g.BodyData) {
	t_chanout := sp.f.AddTiming("stream_chanout")
	defer t_chanout.Done()

	first := true
	size := 0
	totalsize := uint64(0)
	received := 0
	never_flushed := true
	for {
		bd, gotdata := <-out // gets us a "bodydata"
		if !gotdata {
			if bd != nil {
				panic("developer misunderstood return values of channel")
			}
			if *debug_stream {
				fmt.Printf("[streamproxy] Received %d objects on outchannel (backend->browser)\n", received)
			}
			break
		}
		sdr := bd.Response   // gets us a "StreamDataResponse" (with data and/or metadata)
		resp := sdr.Response // gets us a "StreamResponse" (metadata)
		received++
		//		fmt.Printf("[streamproxy] Writing %d bytes to browser (first=%v)\n", len(data.Data), first)

		if resp != nil {
			if !first {
				fmt.Printf("[streamproxy] meta data received AFTER data (%d bytes) was received\n", size)
			} else {
				if *debug_stream {
					fmt.Printf("[streamproxy] Received stream response (code=%d)\n", resp.StatusCode)
				}
				sp.processStreamResponse(resp)
				totalsize = resp.Size
				first = false
			}
		}
		if sp.f.writer == nil {
			panic("writer is nil")
		}
		if (sdr != nil) && len(sdr.Data) > 0 {
			if *debug_stream {
				fmt.Printf("Received %d bytes from backend\n", len(sdr.Data))
			}
			size = size + len(sdr.Data)
			err := sp.f.Write(sdr.Data)
			if err != nil {
				fmt.Printf("WRITE ERROR: %s\n", err)
				sp.write_err = err
				break
			}
			if sp.f.hf.def.LowLatency || never_flushed || *always_flush {
				sp.f.Flush()
				never_flushed = false
			}
		}
		if *debug {
			fmt.Printf("[streamproxy] wrote %s of %s (chunk %d) bytes to browser\n", humanize.Bytes(uint64(size)), humanize.Bytes(totalsize), len(sdr.Data))
		}
	}
	/*
		if first && received > 0 {
			sp.processStreamResponse(resp)
		}
	*/
	wg.Done()
	if *debug {
		fmt.Printf("[streamproxy] outchannel done\n")
	}
}

func fixIP(remoteaddr string) string {
	res := ""
	if strings.Contains(remoteaddr, "]:") {
		//ip6 is something like: [::1]:12312
		xs := strings.Split(remoteaddr, "]:")
		res = xs[0][1:]
	} else if strings.Contains(remoteaddr, ":") {
		xs := strings.Split(remoteaddr, ":")
		res = xs[0]
	}
	return res
}

func ExperimentalMode() bool {
	return *experimental
}
