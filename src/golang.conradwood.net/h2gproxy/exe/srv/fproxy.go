package srv

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"

	"golang.conradwood.net/apis/antidos"
	apb "golang.conradwood.net/apis/auth"
	"golang.conradwood.net/apis/h2gproxy"
	h2g "golang.conradwood.net/apis/h2gproxy"
	ic "golang.conradwood.net/apis/rpcinterceptor"
	us "golang.conradwood.net/apis/usagestats"
	"golang.conradwood.net/go-easyops/client"
	"golang.conradwood.net/go-easyops/common"
	"golang.conradwood.net/go-easyops/errors"
	"golang.conradwood.net/go-easyops/prometheus"

	//	"golang.conradwood.net/go-easyops/tokens"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.conradwood.net/go-easyops/authremote"
	"golang.conradwood.net/go-easyops/utils"
	"golang.conradwood.net/h2gproxy/httplogger"
	"golang.conradwood.net/h2gproxy/shared"
	"golang.yacloud.eu/apis/session"
)

const (
	DEFAULT_MAX_IDLE_TIME = time.Duration(30) * time.Second
)

var (
	always_http    = flag.Bool("redirect_http_only", false, "if true rewrite all redirects to use http instead of https")
	cookie_domain  = flag.Bool("set_cookie_domain", true, "if true set a cookie domain for authentication")
	debugf_counter = 0
	debugf_lock    sync.Mutex
)

type FProxy struct {
	reqidlock                sync.Mutex
	fproxy_lock              sync.Mutex
	response_released        bool
	response_stack           string // string describing where response was released
	response_headers_written bool
	response_headers         map[string]string
	hf                       *HTTPForwarder
	writer                   http.ResponseWriter
	req                      *http.Request
	clientReqHost            string // the hostname the client requested (value of req.host when we received the request)
	loginProxy               bool
	statusCode               int
	ResponseTime             time.Duration
	remoteHost               string
	Errorurl                 *url.URL
	targetHost               string
	Started                  time.Time
	headers_in               string
	headers_out              string
	headers_received         string
	headers_to_backend       string
	scheme                   string // how did the browser connect to us? http/https?
	// once authenticated, this is the user
	signeduser           *apb.SignedUser
	unsigneduser         *apb.User
	proxyResponse        *http.Response
	requested_host       string         // the host as requested by the client
	md                   *ic.InMetadata // the metadata in the context
	ctx                  context.Context
	request_id           string
	redirectedToWeblogin bool
	authResult           *authResult
	Timings              []*Timing
	body                 []byte
	body_read            bool
	form_parsed          bool
	err                  error
	antidos_notified     bool
	port                 int // the port the request came in on
	added_cookies        map[string]*h2gproxy.Cookie
	session              *session.Session       //*apb.SignedSession
	logreq               httplogger.HTTPRequest // to log start/end and updates for this request
	parsedrequest        *parsed_request
	browserconfig        *h2gproxy.BrowserConfig
	print_counter        int
}

func NewFProxy(w http.ResponseWriter, r *http.Request, h *HTTPForwarder, tls bool, port int) *FProxy {

	// create new fproxy
	res := &FProxy{
		port:       port,
		statusCode: 200,
		Started:    time.Now(),
	}
	debugf_lock.Lock()
	debugf_counter++
	if debugf_counter > 99 {
		debugf_counter = 1
	}
	res.print_counter = debugf_counter
	debugf_lock.Unlock()

	// we do this as soon as we can to get accurate reading
	res.hf = h
	res.writer = w
	res.req = r
	res.scheme = r.URL.Scheme
	if res.scheme == "" {
		if tls {
			res.scheme = "https"
		} else {
			res.scheme = "http"
		}
	}
	res.loginProxy = false
	res.logreq = httplogger.DefaultHTTPLogger().RequestStarted(res.FullURL(), res.PeerIP())
	return res
}

func (f *FProxy) Api() uint32 {
	return shared.ApiType(f.hf.def)
}
func (f *FProxy) NeedsAuth() bool {
	return f.hf.def.NeedAuth
}

func (f *FProxy) GetUser() *apb.User {
	return f.unsigneduser
}
func (f *FProxy) SetUser(a *apb.SignedUser) {
	if a == nil {
		if f.signeduser != nil {
			f.Printf("[fproxy] cleared user\n")
		}
		if f.md != nil {
			f.md.UserID = ""
			f.md.User = nil
			f.md.SignedUser = nil
		}
		f.signeduser = nil
		f.unsigneduser = nil
		return
	}
	u := common.VerifySignedUser(a)
	if u == nil {
		return
	}
	f.signeduser = a
	f.unsigneduser = u
	if f.md != nil {
		f.md.UserID = u.ID
		f.md.User = u
		f.md.SignedUser = a
	}
	//f.Printf("[fproxy] set user\n")

}

func (f *FProxy) GoodRequest() {
	if f.antidos_notified == true {
		return
	}
	go func(ff *FProxy) {
		ip := ff.PeerIP()
		_, err := antidos.GetAntiDOSClient().GoodRequest(authremote.Context(), &antidos.IPGoodRequest{IP: ip})
		if err == nil {
			ff.antidos_notified = true
			return
		}
		f.Printf("ANTIDOS: could not report ip \"%s\" to anti-dos system (as good): %s\n", ip, utils.ErrorString(err))
	}(f)

}
func (f *FProxy) AntiDOS(format string, args ...interface{}) { // call antidos IPFailure()
	if f.antidos_notified == true {
		return
	}
	p := "nopath "
	if f.req != nil && f.req.URL != nil {
		p = f.req.URL.Path
	}
	if f.hf != nil && f.hf.def != nil {
		p = p + ", " + f.hf.def.ConfigName
	}
	p = "[" + p + "] "
	msg := fmt.Sprintf(format, args...)
	msg = p + msg
	ip := f.PeerIP()
	adreq := &antidos.IPFailureRequest{
		IP:      ip,
		Message: msg,
	}
	if f.unsigneduser != nil {
		//add user if one
		adreq.UserID = f.unsigneduser.ID
	}
	_, err := antidos.GetAntiDOSClient().IPFailure(authremote.Context(), adreq)
	if err == nil {
		f.antidos_notified = true
		return
	}
	f.Printf("ANTIDOS: could not report ip \"%s\" to anti-dos system (as bad): %s\n", ip, utils.ErrorString(err))
}

// similiar to RequestValues(), but only query parameters, thus can be used if released
func (f *FProxy) QueryValues() map[string]string {
	values := f.req.URL.Query()
	res := make(map[string]string)
	for k, v := range values {
		if len(v) == 0 {
			continue
		}
		res[k] = v[0]
	}
	return res
}

func (f *FProxy) GetForm() (*parsed_request, error) {
	if f.parsedrequest != nil {
		return f.parsedrequest, nil
	}
	f.RequestBody() // ParseForm() actually does funny things to the body. we make sure we read it before we parse it
	pr, err := NewParsedForm(f)
	if err != nil {
		return nil, err
	}
	f.parsedrequest = pr
	return pr, nil
}

// return the values submitted by the client (GET & Post & form)
// this must not be called if fproxy was Released()...
func (f *FProxy) RequestValues() map[string]string {
	hf, err := f.GetForm()
	if f.ProcessError(err, 500, "unable to parse browser login request") {
		return nil
	}
	return hf.RequestValues()
}
func (f *FProxy) RequestValuesMulti() map[string][]string {
	hf, err := f.GetForm()
	if f.ProcessError(err, 500, "unable to parse browser login request") {
		return nil
	}
	return hf.RequestValuesMulti()
}

// silimar to requestvalues, but in proto format
func (f *FProxy) H2GParameters() []*h2gproxy.Parameter {
	var res []*h2gproxy.Parameter
	for k, v := range f.RequestValues() {
		res = append(res, &h2gproxy.Parameter{Name: k, Value: v})
	}
	return res
}

// return the request body
func (f *FProxy) RequestBody() []byte {
	if f.response_released {
		f.Printf("Response was released here:\n%s\n----------------\n-----------\n", f.response_stack)
		panic("requestbody() cannot be called after release")
	}
	if f.body_read {
		return f.body
	}
	body, err := ioutil.ReadAll(f.req.Body)
	//	f.Printf("BODY: \"%s\"\n", string(body))
	if f.ProcessError(err, 500, "unable to parse browser login request") {
		return nil
	}
	f.body = body
	f.body_read = true
	return f.body
}

func (ir *FProxy) AddTiming(name string) *Timing {
	t := NewTiming(name)
	ir.Timings = append(ir.Timings, t)
	return t
}
func (f *FProxy) PeerIP() string {
	if f.remoteHost != "" {
		return f.remoteHost
	}
	h := f.req.RemoteAddr
	return h
}
func (f *FProxy) RequestedQuery() string {
	return f.req.URL.RawQuery
}
func (f *FProxy) RequestedHost() string {
	return f.req.Host
}
func (f *FProxy) RequestedPath() string {
	return f.req.URL.Path
}

// this means fproxy won't be responsible for the response. It's an error to send data through fproxy thereafter
func (f *FProxy) ReleaseResponse() {
	f.response_released = true
	f.response_stack = utils.GetStack("RESPONSE_STACK ")
}

// internal function
func (f *FProxy) write_headers() {
	/*
		if !f.body_read {
			f.Printf("writing headers before body was read\n")
		}
	*/
	if f.response_released || f.response_headers_written {
		return
	}
	for k, v := range f.response_headers {
		f.writer.Header().Set(k, v)
	}

	// write headers...
	if f.added_cookies != nil {
		for _, cookie := range f.added_cookies {
			hc := &http.Cookie{Name: cookie.Name,
				Value:    cookie.Value,
				Path:     "/",
				SameSite: http.SameSiteNoneMode,
				Secure:   true,
				Domain:   f.CookieDomain(),
			}
			if cookie.Expiry != 0 {
				hc.Expires = time.Unix(int64(cookie.Expiry), 0)
			}
			http.SetCookie(f.writer, hc)
		}
	}

	f.writer.WriteHeader(f.statusCode)
	if *debug {
		f.Printf("[fproxy] headers written\n")
	}
	f.response_headers_written = true
}
func (f *FProxy) SetStatus(code int) {
	if code == f.statusCode {
		return
	}
	if f.response_headers_written {
		f.Printf("[%s] WARNING attempt to set http code to %d (previously %d) after headers were written\n", f.String(), code, f.statusCode)

	}
	f.statusCode = code
}

func (f *FProxy) RedirectTo(url string, forceget bool) {
	if *debug || *debug_redirect {
		f.Printf("Redirecting to \"%s\"\n", url)
	}
	if *always_http && strings.HasPrefix(url, "https://") {
		url = "http://" + url[7:]
		f.Printf("(http downgrade): Redirecting to \"%s\"\n", url)
	}
	f.SetHeader("Location", url)
	if forceget {
		f.SetStatus(303)
	} else {
		f.SetStatus(307)
	}
	f.write_headers()
}

// all lowercased
func (f *FProxy) RequestHeaders() map[string]string {
	res := make(map[string]string)
	for k, v := range f.req.Header {
		if len(v) < 1 {
			continue
		}
		res[strings.ToLower(k)] = v[0]
	}
	return res
}

// all lowercased
func (f *FProxy) H2GHeaders() []*h2gproxy.Header {
	var res []*h2gproxy.Header
	for k, v := range f.req.Header {
		h := &h2gproxy.Header{Name: k, Values: v}
		res = append(res, h)
	}
	return res
}
func (f *FProxy) GetHeader(key string) string {
	if f.req == nil {
		return ""
	}
	key = strings.ToLower(key)
	for hn, hvs := range f.req.Header {
		hn = strings.ToLower(hn)
		if key != hn {
			continue
		}
		if len(hvs) == 0 {
			return ""
		}
		return hvs[0]
	}
	return ""
}

func (f *FProxy) SetHeader(key, value string) {
	if f.response_headers_written {
		f.Printf("late set header %s=%s\n", key, value)
	}
	if f.response_headers == nil {
		f.response_headers = make(map[string]string)
	}
	f.response_headers[key] = value
}
func (f *FProxy) Flush() {
	if f.response_released {
		panic("flush after response was released")
	}
	f.write_headers()
	flusher, isFlusher := f.writer.(http.Flusher) // some http responsewriters implement "flusher" interface
	if isFlusher {
		flusher.Flush() // send the data immediately to the client
	}

}
func (f *FProxy) GetContentType() string {
	return f.GetHeader("content-type")
}

// writes headers too
func (f *FProxy) Write(buf []byte) error {
	if !f.body_read {
		//	f.Printf("writing before body was read\n")
	}
	/*
		if *debug {
			f.Printf("[fproxy] Writing %d bytes\n", len(buf))
		}
	*/
	if f.response_released {
		panic("write after response was released")
	}

	//	f.SetHeader("content-length", fmt.Sprintf("%d", len(buf)))
	f.write_headers()
	// posix is ambigous here. 0 is not an error if is not a file (I think)
	b, err := f.writer.Write(buf)
	if err != nil {
		return err
	}
	if (b != 0) && (b != len(buf)) {
		return fmt.Errorf("partial write: %d bytes of %d", b, len(buf))
	}
	return nil
}
func (f *FProxy) WriteString(buf string) {
	f.Write([]byte(buf))
}

func (f *FProxy) SetCookies(cookies []*h2gproxy.Cookie) {
	for _, c := range cookies {
		f.AddCookie(c)
	}
}

func (f *FProxy) AddCookie(cookie *h2gproxy.Cookie) {
	if len(cookie.Name) == 0 || cookie.Name[0] == '.' {
		panic(fmt.Sprintf("invalid cookie (%s)", cookie.Name))
	}
	f.fproxy_lock.Lock()
	if f.added_cookies == nil {
		f.added_cookies = make(map[string]*h2gproxy.Cookie)
	}
	f.fproxy_lock.Unlock()
	f.added_cookies[cookie.Name] = cookie

	//	f.setCookie(hc)
}

// the authcookie is a bit special
func (f *FProxy) setCookie(cookie *http.Cookie) {
	http.SetCookie(f.writer, cookie)
}

// if true, one can no longer access body or form values
func (f *FProxy) IsReleased() bool {
	return f.response_released
}
func (f *FProxy) Close() {
	if f.response_released {
		return
	}
	f.Debugf("closed, status code %d\n", f.statusCode)
	f.write_headers()
}
func (f *FProxy) String() string {
	hf := f.hf
	if hf == nil {
		return "fproxy without forwarder"
	}
	def := hf.def
	if def == nil {
		return "fproxy without httpdef"
	}
	return fmt.Sprintf("config=%s,path=%s", def.ConfigName, def.URLPath)
}

func (f *FProxy) ObserveTiming(t time.Duration) {
	mn := escapeMetric(f.hf.def.ConfigName)
	timsummary.With(prometheus.Labels{"config": mn}).Observe(t.Seconds())
}
func (f *FProxy) userString() string {
	if f.unsigneduser == nil {
		return "ANONYMOUS"
	}
	return fmt.Sprintf("#%s(%s)", f.unsigneduser.ID, f.unsigneduser.Email)
}

func (f *FProxy) createUserHeaders() (map[string]string, error) {
	res := make(map[string]string)
	if f.unsigneduser != nil {
		res["REMOTE_USER"] = f.unsigneduser.Email
		res["REMOTE_FULLNAME"] = f.unsigneduser.FirstName + " " + f.unsigneduser.LastName
		res["REMOTE_USERID"] = f.unsigneduser.ID
		suser, err := utils.Marshal(f.unsigneduser)
		if err != nil {
			f.Printf("Failed to marshal user: %s\n", utils.ErrorString(err))
			f.SetAndLogFailure(INTERNAL_ACCESS_DENIED_NONVALID, err)
			return nil, err
		}
		res["X-SIGNEDUSER"] = suser

		suser, err = utils.Marshal(f.signeduser)
		if err != nil {
			f.Printf("Failed to marshal signed user: %s\n", utils.ErrorString(err))
			f.SetAndLogFailure(INTERNAL_ACCESS_DENIED_NONVALID, err)
			return nil, err
		}
		res["X-USERWITHSIGNATURE"] = suser
		authheader := f.unsigneduser.Email + ":foo"
		authheader64 := base64.StdEncoding.EncodeToString([]byte(authheader))
		res["AUTHORIZATION"] = fmt.Sprintf("Basic %s", authheader64)

	}
	return res, nil
}

func (f *FProxy) CookieDomain() string {
	if !*cookie_domain {
		return ""
	}
	cr := f.clientReqHost
	i := strings.Index(cr, ".")
	if i == -1 {
		return ""
	}
	cr = cr[i:]
	// may include a port
	i = strings.Index(cr, ":")
	if i != -1 {
		cr = cr[:i]
	}
	return cr
}

func (f *FProxy) SubmittedCookies() []*h2gproxy.Cookie {
	var res []*h2gproxy.Cookie
	if f.req == nil {
		return res
	}
	for _, c := range f.req.Cookies() {
		hc := &h2gproxy.Cookie{
			Name:   c.Name,
			Value:  c.Value,
			Expiry: uint32(c.Expires.Unix()),
		}
		res = append(res, hc)
	}
	return res
}

// return full url as requested by client
func (f *FProxy) FullURL() string {
	p := f.req.URL.RawPath
	if p == "" {
		p = f.req.URL.Path
	}
	h := f.req.URL.Host
	if h == "" {
		h = f.req.Host
	}
	h = strings.Trim(h, "/")
	p = strings.Trim(p, "/")
	return fmt.Sprintf("%s://%s/%s", f.scheme, h, p)
}

// dependening on the useragent, figures out if CLI or browser
func (f *FProxy) IsKnownCLITool() bool {
	return shared.IsKnownCLITool(f.UserAgent())
}

// return the useragent header
func (f *FProxy) UserAgent() string {
	s := f.GetHeader("user-agent")
	return s
}
func (f *FProxy) authenticateUser(user, pw string) (*apb.SignedUser, error) {
	if strings.HasSuffix(user, ".token") {
		// assuming userid & token instead of user and password
		return f.authenticateByUserIDAndToken(user, pw)
	}
	ctx := authremote.Context()
	//ctx := createBootstrapContext()
	cr, err := authproxy.SignedGetByPassword(ctx, &apb.AuthenticatePasswordRequest{Email: user, Password: pw})
	if err != nil {
		f.Printf("Failed to authenticate user %s: %s (from %s, accessing %s)\n", user, utils.ErrorString(err), f.PeerIP(), f.String())
		return nil, err
	}
	if !cr.Valid {
		fmt.Println(cr.LogMessage)
		return nil, fmt.Errorf("%s", cr.PublicMessage)
	}
	u := common.VerifySignedUser(cr.User)
	if u == nil {
		return nil, fmt.Errorf("invalid user-signature")
	}
	if !u.Active {
		f.Printf("not active\n")
		return nil, fmt.Errorf("Not active")
	}
	if *debug {
		f.Printf("Authenticated user %s %s (%s): \n", u.FirstName, u.LastName, u.Email)
	}
	return cr.User, nil
}

// expect user in the format of [USERID].token and pw to be a token
// error if cannot be authenticated
func (f *FProxy) authenticateByUserIDAndToken(user, pw string) (*apb.SignedUser, error) {
	userid := strings.TrimSuffix(user, ".token")
	ctx := authremote.Context()
	cr, err := authproxy.SignedGetByToken(ctx, &apb.AuthenticateTokenRequest{Token: pw})
	if err != nil {
		return nil, err
	}
	if !cr.Valid {
		fmt.Println(cr.LogMessage)
		return nil, fmt.Errorf("%s", cr.PublicMessage)
	}
	u := common.VerifySignedUser(cr.User)
	if u == nil {
		return nil, fmt.Errorf("invalid user-signature")
	}
	if !u.Active {
		f.Printf("not active\n")
		return nil, fmt.Errorf("Not active")
	}
	if u.ID != userid {
		f.Printf("Userid mismatch (\"%s\"!=\"%s\")\n", userid, u.ID)
		return nil, fmt.Errorf("wrong userid")
	}
	if *debug {
		f.Printf("Authenticated user %s %s (%s): \n", u.FirstName, u.LastName, u.Email)
	}
	return cr.User, nil

}

func verify_user(f *FProxy) {
	if f.unsigneduser == nil {
		return
	}
	if f.unsigneduser.EmailVerified == false {
		f.Printf("[verifyuser] User email is not verified. not accepting user\n")
		f.SetUser(nil)
	}
}

// report http failure to antidos
func (f *FProxy) ReportHTTPFailure() {

}

func (f *FProxy) Debugf(format string, args ...interface{}) {
	if !*debug {
		return
	}
	f.Printf(format, args...)
}
func (f *FProxy) Printf(format string, args ...interface{}) {
	debugf_lock.Lock()
	defer debugf_lock.Unlock()
	user := ""
	if f.unsigneduser != nil {
		user = f.unsigneduser.Abbrev + " "
	}

	cfgname := "nocfg"
	if f.hf != nil && f.hf.def != nil && f.hf.def.ConfigName != "" {
		cfgname = f.hf.def.ConfigName
	}
	prefix := fmt.Sprintf("[%03d debug %s%s] ", f.print_counter, user, cfgname)
	txt := fmt.Sprintf(format, args...)
	fmt.Print(prefix + txt)
}

func (f *FProxy) GetRequestID() string {
	if f.request_id != "" {
		return f.request_id
	}
	f.reqidlock.Lock()
	if f.request_id != "" {
		f.reqidlock.Unlock()
		return f.request_id
	}
	f.request_id = utils.RandomString(12)
	f.reqidlock.Unlock()
	return f.request_id
}

// request could not be made, we log the fact
// (e.g. no backend is available)
func (f *FProxy) SetAndLogFailure(code int32, be_err error) {
	var err error
	f.SetStatus(int(code))
	f.Printf("Failed forwarding \"%s\" to \"%s\": code=%d for user %s\n", f.hf.def.TargetService, f.targetHost, code, f.currentUser())
	reqCounter.With(prometheus.Labels{
		"name":          f.hf.def.ConfigName,
		"targetservice": f.hf.def.TargetService,
		"statuscode":    fmt.Sprintf("%d", f.statusCode),
		"targethost":    f.targetHost}).Inc()
	statusCounter.With(prometheus.Labels{
		"name":          f.hf.def.ConfigName,
		"targetservice": f.hf.def.TargetService,
		"statuscode":    normalizeStatusCode(f.statusCode),
		"targethost":    f.targetHost}).Inc()

	f.logreq.RequestFinished(uint32(code), f.hf.def.TargetService, "", be_err)

	f.AddContext()

	if *debug {
		f.Printf("using context %v to log call\n", f.BootstrapContext())
	}
	if *logusage {
		if usageStatsClient == nil {
			usageStatsClient = us.NewUsageStatsServiceClient(client.Connect("usagestats.UsageStatsService"))
		}
		_, err = usageStatsClient.LogHttpCall(f.BootstrapContext(), &us.LogHttpCallRequest{
			Url:       f.req.URL.String(),
			Success:   false,
			Timestamp: uint32(f.Started.Unix()),
		})

		if err != nil {
			f.Printf("failed backend call: failed to update usage stats %s\n", utils.ErrorString(err))
		}
	}
}

func default_canceller() {
}

// returns a context suitable for calling backends
func (f *FProxy) UserContext() (context.Context, context.CancelFunc) {
	if f.authResult == nil {
		return createBootstrapContext(), default_canceller
	}

	nctx, cf, err := createCancellableContext(f, f.authResult)
	if err != nil {
		f.Printf("failed to create user context: %s\n", errors.ErrorString(err))
		return createBootstrapContext(), default_canceller
	}
	return nctx, cf
}

// returns a context suitable for calling things like "auth"
func (f *FProxy) BootstrapContext() context.Context {
	if f.ctx != nil {
		return f.ctx
	}
	return createBootstrapContext()
}

func (f *FProxy) MaxIdleTime() time.Duration {
	if f.hf.def.MaxIdleTime == 0 {
		return DEFAULT_MAX_IDLE_TIME
	}
	return time.Duration(f.hf.def.MaxIdleTime) * time.Second
}

func (f *FProxy) TargetService() string {
	return f.hf.def.TargetService
}

func (f *FProxy) ByteRanges() []*h2g.ByteRange {
	bs, err := parseByteRange(f.GetHeader("range"))
	if err != nil {
		f.Printf("WARNING - invaliad byte range: \"%s\"\n", err)
		return nil
	}
	return bs
}

// noop???
func (f *FProxy) SetFilename(name string) {
}
func (f *FProxy) SetContentType(mimetype string) {
	f.SetHeader("content-type", mimetype)
}
func (f *FProxy) SetContentLength(size uint64) {
	f.SetHeader("Content-Length", fmt.Sprintf("%d", size))
}
func (f *FProxy) SetError(err error) {
	if err == nil {
		return
	}
	//	st := status.Convert(err)
	f.err = err
	f.SetStatus(shared.ConvertErrorToCode(err))
	s := fmt.Sprintf("error: %s", f.err)
	f.WriteString(s)
}

// return true if it found an error (err != nil)
func (f *FProxy) ProcessError(err error, code int, msg string) bool {
	if err == nil {
		return false
	}
	f.err = err
	f.SetStatus(code)
	f.WriteString(msg)
	if f.IsDebugHeaderGroup(f.GetUser()) {
		f.WriteString("-- full errormessage:<br/>")
		f.WriteString(utils.ErrorString(err))
	}
	f.Printf("Error %s on %s (reported \"%s\" to user)\n", err, f.req.URL.Path, msg)
	return true
}

func (f *FProxy) BrowserConfig() *h2gproxy.BrowserConfig {
	res := f.browserconfig
	if res != nil {
		return res
	}
	return browserconfig_default()

}
func (f *FProxy) ConfigName() string {
	return f.hf.def.ConfigName
}
