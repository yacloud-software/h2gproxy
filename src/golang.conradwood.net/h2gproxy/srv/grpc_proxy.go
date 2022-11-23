package srv

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	fw "golang.conradwood.net/apis/framework"
	h2g "golang.conradwood.net/apis/h2gproxy"
	ic "golang.conradwood.net/apis/rpcinterceptor"
	"golang.conradwood.net/go-easyops/auth"
	"golang.conradwood.net/go-easyops/client"
	"golang.conradwood.net/go-easyops/errors"
	"golang.conradwood.net/go-easyops/tokens"
	"golang.conradwood.net/go-easyops/utils"
	"google.golang.org/grpc/codes"
	_ "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"strings"
	"time"
)

var (
	rc            ic.RPCInterceptorServiceClient
	send_www_auth = flag.Bool("grpc_proxy_send_www_auth", false, "if true send a 'Basic' www-authenticate header whenever the backend requires authentication to complete a call. if false, send an empty www-authenticate header")
	print_rpc     = flag.Bool("print_rpc", false, "print rpc payload before calling gRPC backends")
	debug_rpc     = flag.Bool("debug_grpc_proxy", false, "debug grpc proxy")
)

type GRPCProxy struct {
	f                     *FProxy
	p                     ProxyConfig
	AcceptUnverifiedUsers bool
}

type ProxyConfig interface {
	Serve(ctx context.Context, in *h2g.ServeRequest) (*h2g.ServeResponse, error)
}

func NewGrpcProxy(f *FProxy, p ProxyConfig) *GRPCProxy {
	return &GRPCProxy{f: f, p: p, AcceptUnverifiedUsers: false}
}

// we forward via grpc...
func (g *GRPCProxy) Proxy() {
	if *printHeaders {
		fmt.Println(headersToString(g.f.req.Header))
	}
	if rc == nil {
		rc = ic.NewRPCInterceptorServiceClient(client.Connect("rpcinterceptor.RPCInterceptorService"))
	}
	var err error
	a := &authResult{}
	a, err = json_auth(g.f) // always check if we got auth stuff
	if a.Authenticated() {
		g.f.GoodRequest()
	}
	if g.f.hf.def.NeedAuth && !a.Authenticated() {
		g.f.AntiDOS("needs auth but got none")
		if err != nil {
			if *debug_rpc {
				fmt.Printf("[grpcproxy] Failed to proceed with authentication (error: %s)\n", err)
			}
			return
		}
		// if we tried and failed it's forbidden. otherwise send challenge
		if a.GotCredentials() {
			g.f.err = errors.AccessDenied(tokens.ContextWithToken(), "access denied for user %s", a.User())
			g.f.SetStatus(401) // maybe this should be 401?
			g.f.Write([]byte("access denied"))
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
		FooBar:       "h2gproxy-grpcproxy",
		RequestID:    "", // we want a new one
		UserToken:    "", //do we?
		ServiceToken: tokens.GetServiceTokenParameter(),
	}
	if a != nil && (a.User() != nil) {
		g.f.SetUser(a.SignedUser())
	}
	// safety check: need auth but got no user? - decline
	if g.f.hf.def.NeedAuth && g.f.signeduser == nil {
		if *debug {
			fmt.Printf("[grpcproxy] need user but do not have one (==401)\n")
		}
		g.f.AntiDOS("need auth but got no signeduser")
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
		fmt.Printf("[grpcprocy] Failed to call intercept rpc: %s\n", utils.ErrorString(err))
		return
	}
	g.f.requestid = rp.RequestID
	late_auth_attempted := false
retry:
	// check for non-verified users
	if g.f.unsigneduser != nil && g.f.unsigneduser.EmailVerified == false && !g.AcceptUnverifiedUsers {
		g.f.SetUser(nil) // we never pass an unverified user along!!
		g.f.md.UserID = ""
	}

	g.f.Started = time.Now()
	/************ now call the backend ****************************/
	nctx, err := g.grpcproxy(rp, a)
	//	elapsed := time.Now().Sub(g.f.Started)
	//	ms := elapsed.Nanoseconds() / 1000 / 1000
	g.f.ResponseTime = time.Since(g.f.Started)

	var httpError *HTTPError
	public_error_message := ""
	privileged_error_message := ""
	/******************** did the backend return an error ? ******************/
	if err != nil {
		if g.f.unsigneduser == nil { // if not authenticated and error, tell antidos about it
			if antidos_err(err) {
				g.f.AntiDOS("backend serving returned error (%s) and no unsigneduser", err)
			}
		}
		g.f.err = err
		st := status.Convert(err)
		public_error_message = get_public_error_message(err)
		privileged_error_message = utils.ErrorString(err)
		message := st.Message()
		code := st.Code()
		msg := fmt.Sprintf("[grpcproxy] API (type %d) Call (%s), authenticated()=%v, late_auth=%v, failed: code=%d message=%s", g.f.hf.def.Api, g.f.String(), a.Authenticated(), late_auth_attempted, code, message)
		if *debug_rpc {
			fmt.Println(msg)
			fmt.Printf("[grpcproxy] API (type %d) Call (%s) failed: %s\n", g.f.hf.def.Api, g.f.String(), utils.ErrorString(err))
		}
		// sometimes the backend (especially the html backend) may ask us to authenticate a user
		// this happens, if, for example some parts of a backend are accessible by anyone (even non-authenticated people)
		// and some need authentication. we deal with this here.

		// sometimes we actually identified a user (but user is not yet verified)
		if a.User() != nil && !a.User().EmailVerified && a.Authenticated() && !late_auth_attempted {
			late_auth_attempted = true
			g.f.SetUser(a.SignedUser())
			if *debug_rpc {
				fmt.Printf("[grpcproxy] have user %s, but email not verified, thus it was not passed to the backend\n", auth.Description(a.User()))
			}
			nctx, err := createContext(g.f, a, rp)
			if err != nil {
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
			if *debug_rpc {
				fmt.Printf("[gprcproxy] Late authentication\n")
			}
			late_auth_attempted = true
			b := g.late_authenticate()
			if b {
				goto retry
			}
			return
		}

		g.f.customHeaders(&ExtraInfo{Error: err, Message: msg})

		httpError = grpcToHTTPMap[code]
		httpError.ErrorMessage = public_error_message
		if auth.IsRoot(nctx) {
			httpError.ExtendedErrorString = privileged_error_message
		}

		g.f.SetStatus(httpError.ErrorCode)

		resp, err := json.Marshal(httpError)
		if err != nil {
			fmt.Printf("Failed to marshal http error: %s\n", err)
		}
		g.f.Write(resp)
	}

	g.f.LogResponse()
	return
}

// returns the context we used to call the function...
func (g *GRPCProxy) grpcproxy(rp *ic.InterceptRPCResponse, a *authResult) (context.Context, error) {
	/***************************************************************
	// build the proto to call jsonapimultiplexer or others
	***************************************************************/
	// read the request:
	body := g.f.RequestBody()

	// build up the grpc proto
	sv := &h2g.ServeRequest{Body: string(body)}
	sv.Host = strings.ToLower(g.f.req.Host)
	sv.Path = g.f.req.URL.Path
	sv.Method = g.f.req.Method
	sv.SourceIP = fixIP(g.f.req.RemoteAddr)

	for name, values := range g.f.req.Header {
		if strings.ToLower(name) == "user-agent" && len(values) > 0 {
			sv.UserAgent = values[0]
		}
		h := &h2g.Header{Name: name}
		sv.Headers = append(sv.Headers, h)
		h.Values = values
	}
	err := AddUserHeaders1(g.f, sv)
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
	//fmt.Printf("Context with user: %v\n", g.f.user)
	var ctx context.Context
	nctx, err := createContext(g.f, a, rp)
	if err != nil {
		fmt.Printf("[grpcproxy] failed to create a new context: %s\n", utils.ErrorString(err))
		return nil, err
	} else {
		ctx = nctx
	}
	/*
		if *debug {
			md, ok := metadata.FromOutgoingContext(ctx)
				fmt.Printf("[grpcproxy] Invoking with ctx = %#v\n", ctx)
				fmt.Printf("[grpcproxy] (%v): Metadata = %v\n", ok, md)
		}
	*/
	g.f.ctx = ctx

	if *print_rpc || *printHeaders {
		for _, h := range sv.Headers {
			fmt.Printf("[grpcproxy] request headers: %s=%s\n", h.Name, strings.Join(h.Values, ","))
		}
	}
	if *print_rpc {
		for _, h := range sv.Parameters {
			fmt.Printf("[grpcproxy] request parameters: %s=%s\n", h.Name, h.Value)
		}
		fmt.Printf("[grpcproxy] request body: \"%s\"\n", sv.Body)
		fmt.Printf("[grpcproxy] request path: \"%s\"\n", sv.Path)
		fmt.Printf("[grpcproxy] request method: \"%s\"\n", sv.Method)
		fmt.Printf("[grpcproxy] request method: \"%s\"\n", sv.Method)
	}
	/***************************************************************
	// make the RPC Call
	***************************************************************/
	sv.SessionToken, _ = g.f.GetSessionToken()
	resp, err := g.p.Serve(ctx, sv) // calls the backend
	g.f.add_session_cookie(resp, err)
	if err != nil {
		if *debug {
			fmt.Printf("[grpcproxy] returned from Serve() with error: %s\n", utils.ErrorString(err))
		}
		if g.f.unsigneduser == nil {
			if antidos_err(err) {
				// a grpc call failed without a user account
				g.f.AntiDOS("serve returned error (no user): %s", err)
			}
		}
		// must return on or other here, not both
		if resp != nil {
			return ctx, nil
		} else {
			return ctx, err
		}
	}
	if *debug {
		fmt.Printf("[grpcproxy] returned httpresponsecode=%d and grpccode=%d\n", resp.HTTPResponseCode, resp.GRPCCode)
	}
	code := int(resp.HTTPResponseCode)
	if code == 0 {
		if len(resp.Body) == 0 {
			code = 204
		} else {
			code = 200
		}
	}
	g.f.SetStatus(code)

	if resp.RedirectToSlash {
		fmt.Printf("received redirect_to_slash_request.\n")
		g.f.RedirectTo(g.f.FullURL()+"/", false)
		//		code = 307
		//		g.f.addHeader("location", g.f.FullURL()+"/")
	}

	mtype := "application/json"
	if resp.MimeType != "" {
		mtype = resp.MimeType
	}
	// set cookies if we are asked to do so
	for _, c := range resp.Cookies {
		//cookie := &h2g.Cookie{Name: c.Name, Value: c.Value, Expiry: time.Unix(int64(c.Expiry))}
		g.f.AddCookie(c)
		fmt.Printf("Setting cookie %s, as instructed from backend\n", c.Name)

	}
	g.f.SetHeader("content-type", fmt.Sprintf("%s; charset=utf-8", mtype))
	reqid := "NA"
	if rp != nil {
		reqid = rp.RequestID
	}
	if *debug {
		fmt.Printf("Setting requestid header to \"%s\"\n", reqid)
	}

	g.f.customHeaders(nil)
	g.f.SetHeader("X-LB-RequestID", reqid)

	g.f.SetStatus(code)
	g.f.Write(resp.Body)
	return ctx, err
}

// called AFTER a backend was called and asked us to authenticate the user
// and we already identified the user, but the users email wasn't verified (yet)
func (g *GRPCProxy) verifyEmail(ctx context.Context) bool {
	return g.f.WebVerifyEmail(ctx)
}

// called AFTER a backend was called and asked us to authenticate the user
// depending on the backend it's web or basic or so.
func (g *GRPCProxy) late_authenticate() bool {
	if *debug_rpc {
		fmt.Printf("Authentication request from backend detected.\n")
	}
	// depending on the useragent, we serve html or trigger basic-auth
	if g.f.needsBasicAuth() {
		if *debug_rpc {
			fmt.Printf("[grpcproxy]Cannot do 'late' basic authentication just yet, sorry.")
		}
		if *send_www_auth {
			g.f.SetHeader("WWW-Authenticate", "Basic realm=\"Login\"")
		} else {
			g.f.SetHeader("WWW-Authenticate", "")
		}
		g.f.SetStatus(401)
		g.f.Write([]byte("[grpcproxy] authentication required. you may try passing apikey=XXX as a url parameter or add your credentials to .netrc"))
		return false
	}

	// weblogin
	return g.f.WebLogin()
}
func get_public_error_message(err error) string {
	st, ok := status.FromError(err)
	if !ok {
		// not a valid grpc error
		return ""
	}
	if st.Details() == nil {
		return ""
	}
	for _, a := range st.Details() {
		fmd, ok := a.(*fw.FrameworkMessageDetail)
		if !ok {
			continue
		}
		if *debug_rpc {
			fmt.Printf("Error-Message: %#v\n", fmd)
		}
		//return fmd.Message
		return fmt.Sprintf("%s", st.Message())

	}
	return ""
}

func antidos_err(err error) bool {
	st := status.Code(err)
	if st == codes.NotFound {
		return false
	}
	return true
}
