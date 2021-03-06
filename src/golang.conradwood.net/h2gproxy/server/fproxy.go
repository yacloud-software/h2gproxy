package main

import (
	"context"
	"flag"
	"fmt"
	"golang.conradwood.net/apis/antidos"
	apb "golang.conradwood.net/apis/auth"
	"golang.conradwood.net/apis/h2gproxy"
	ic "golang.conradwood.net/apis/rpcinterceptor"
	"golang.conradwood.net/go-easyops/common"
	"golang.conradwood.net/go-easyops/prometheus"
	"golang.conradwood.net/go-easyops/tokens"
	"golang.conradwood.net/go-easyops/utils"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	always_http   = flag.Bool("redirect_http_only", false, "if true rewrite all redirects to use http instead of https")
	cookie_domain = flag.Bool("set_cookie_domain", true, "if true set a cookie domain for authentication")
)

type FProxy struct {
	fproxy_lock              sync.Mutex
	response_released        bool
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
	requestid            string
	redirectedToWeblogin bool
	authResult           *authResult
	Timings              []*Timing
	body                 []byte
	body_read            bool
	submitted_fields     map[string]string
	form_parsed          bool
	err                  error
	antidos_notified     bool
	port                 int // the port the request came in on
	added_cookies        map[string]*h2gproxy.Cookie
	session_cookie       string
	session              *apb.SignedSession
}

func (f *FProxy) SetUser(a *apb.SignedUser) {
	if a == nil {
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

}

func (f *FProxy) GoodRequest() {
	if f.antidos_notified == true {
		return
	}
	go func(ff *FProxy) {
		ip := ff.PeerIP()
		_, err := antidos.GetAntiDOSClient().GoodRequest(tokens.ContextWithToken(), &antidos.IPGoodRequest{IP: ip})
		if err == nil {
			ff.antidos_notified = true
			return
		}
		fmt.Printf("ANTIDOS: could not report ip \"%s\" to anti-dos system (as good): %s\n", ip, utils.ErrorString(err))
	}(f)

}
func (f *FProxy) AntiDOS(format string, args ...interface{}) {
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
	_, err := antidos.GetAntiDOSClient().IPFailure(tokens.ContextWithToken(), &antidos.IPFailureRequest{IP: ip, Message: msg})
	if err == nil {
		f.antidos_notified = true
		return
	}
	fmt.Printf("ANTIDOS: could not report ip \"%s\" to anti-dos system (as bad): %s\n", ip, utils.ErrorString(err))
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

// return the values submitted by the client (GET & Post & form)
// this must not be called if fproxy was Released()...
func (f *FProxy) RequestValues() map[string]string {
	if f.form_parsed {
		return f.submitted_fields
	}
	f.RequestBody() // ParseForm() actually does funny things to the body. we make sure we read it before we parse it
	err := f.req.ParseForm()

	if f.ProcessError(err, 500, "unable to parse browser login request") {
		return nil
	}

	res := make(map[string]string)
	for name, value := range f.req.Form {
		if len(value) < 1 {
			fmt.Printf("Skipping value %s (%d submits)\n", name, len(value))
			continue
		}
		res[name] = value[0]
		if *debug {
			fmt.Printf("Submitted: %s=%s\n", name, value[0])
		}
	}
	// if it is a post we might have a funny url string (which are also values)
	if f.req.Method == "POST" {
		values, err := url.ParseQuery(string(f.RequestBody()))
		if err == nil {
			for k, v := range values {
				if len(v) < 1 {
					continue
				}
				res[k] = v[0]
			}
		}
	}

	f.submitted_fields = res
	f.form_parsed = true
	return f.submitted_fields
}

// return the request body
func (f *FProxy) RequestBody() []byte {
	if f.response_released {
		panic("requestbody() cannot be called after release")
	}
	if f.body_read {
		return f.body
	}
	body, err := ioutil.ReadAll(f.req.Body)
	//	fmt.Printf("BODY: \"%s\"\n", string(body))
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

// this means fproxy won't be responsible for the response. It's an error to send data through fproxy thereafter
func (f *FProxy) ReleaseResponse() {
	f.response_released = true
}

// internal function
func (f *FProxy) write_headers() {
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
	f.response_headers_written = true
}
func (f *FProxy) SetStatus(code int) {
	f.statusCode = code
}

func (f *FProxy) RedirectTo(url string, forceget bool) {
	if *debug || *debug_redirect {
		fmt.Printf("Redirecting to \"%s\"\n", url)
	}
	if *always_http && strings.HasPrefix(url, "https://") {
		url = "http://" + url[7:]
		fmt.Printf("(http downgrade): Redirecting to \"%s\"\n", url)
	}
	f.SetHeader("Location", url)
	if forceget {
		f.SetStatus(303)
	} else {
		f.SetStatus(307)
	}
	f.write_headers()
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
		fmt.Printf("late set header %s=%s\n", key, value)
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

// writes headers too
func (f *FProxy) Write(buf []byte) error {
	if f.response_released {
		panic("write after response was released")
	}

	//	f.SetHeader("content-length", fmt.Sprintf("%d", len(buf)))
	f.write_headers()
	b, err := f.writer.Write(buf)
	if b != len(buf) {
		return fmt.Errorf("partial write: %d bytes of %d", b, len(buf))
	}
	if err != nil {
		return err
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
func (f *FProxy) Close() {
	if f.response_released {
		return
	}
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
			fmt.Printf("Failed to marshal user: %s\n", utils.ErrorString(err))
			f.SetAndLogFailure(INTERNAL_ACCESS_DENIED_NONVALID)
			return nil, err
		}
		res["X-SIGNEDUSER"] = suser

		suser, err = utils.Marshal(f.signeduser)
		if err != nil {
			fmt.Printf("Failed to marshal signed user: %s\n", utils.ErrorString(err))
			f.SetAndLogFailure(INTERNAL_ACCESS_DENIED_NONVALID)
			return nil, err
		}
		res["X-USERWITHSIGNATURE"] = suser

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
