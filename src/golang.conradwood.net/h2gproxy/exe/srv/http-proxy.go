package srv

// this does http proxying and also sends logging to
// the httpkpi module

// also - the histograms are a bit funny.
// The reason we have different metrics for different services, is that
// we probably want to have different buckets for each
// (otherwise we'd just use a label)

import (
	"bytes"
	"crypto/tls"
	b64 "encoding/base64"
	"flag"
	"fmt"
	apb "golang.conradwood.net/apis/auth"
	pb "golang.conradwood.net/apis/h2gproxy"
	us "golang.conradwood.net/apis/usagestats"
	"golang.conradwood.net/go-easyops/auth"
	"golang.conradwood.net/go-easyops/prometheus"
	//	"golang.conradwood.net/go-easyops/tokens"
	"golang.conradwood.net/go-easyops/utils"
	"golang.conradwood.net/h2gproxy/httplogger"
	"golang.org/x/net/context"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// some errors might occur before we
	// can actually hit our backend
	INTERNAL_ERROR_NO_TARGET           = 601
	INTERNAL_ERROR_NO_LOGIN_BACKEND    = 602
	INTERNAL_ERROR_BUG                 = 603
	INTERNAL_ERROR_CONFIG_ERROR        = 604
	INTERNAL_ACCESS_DENIED_EXTERNAL    = 605
	INTERNAL_ACCESS_DENIED_GROUP       = 403
	INTERNAL_ACCESS_DENIED_NONVALID    = 607
	INTERNAL_ACCESS_DENIED_EMAILVERIFY = 608
)

var (
	auto_flush       = flag.Bool("auto_flush_response", true, "automatically flush the response to the client (stream http responses)")
	stdauth          = flag.Bool("use_stdauth", true, "use standard authentication in http instead of weird one")
	logusage         = flag.Bool("log_usage", false, "if true will log all access to usagestats server")
	enable_acl_paths = flag.Bool("enable_acl_paths", true, "if true, we'll block access to 'internal' urls unless from rfc1918 IP")
	enable_raw_paths = flag.Bool("enable_raw_paths", true, "experimental feature to allow slashes in paths")
	add_hist         = flag.Bool("enable_histogram", true, "set to true to enable histograms")
	enBasicAuth      = flag.Bool("enable_basic_auth", true, "set to true to enable new feature basic auth")
	basicAuth        = flag.Bool("force_basic", false, "set to true to trigger basic authentication in the browser instead of form")
	debugRewrite     = flag.Bool("debug_rewrite", false, "set to true to print rewrite debug information")
	logrequests      = flag.Bool("log_each_request", false, "if you want every single request logged to stdout, enable this")
	debug_groups     = flag.Bool("debug_groups", false, "enable to debug group match issues")
	debug_redirect   = flag.Bool("debug_redirect", false, "enable debug of redirects")
	ip_hack          = flag.Bool("ip_hack", false, "if enabled creates a file in /tmp/h2gproxy/ips for each sending ip")
	debug_throttle   = flag.Bool("debug_throttle", false, "print rate throttling debug information")

	timsummary = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "h2gproxy_req_summary",
			Help: "Summmary for observed requests",
		},
		[]string{"config"},
	)
	reqCounterIn = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "h2gproxy_incoming_http_requests",
			Help: "http requests received (pre-proxy)",
		},
		[]string{"proto", "targetservice", "targethost", "name"},
	)
	reqHostCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "h2gproxy_incoming_http_byhost",
			Help: "V=1 UNIT=ops http requests received by hostname",
		},
		[]string{"name", "host"},
	)
	reqCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "h2gproxy_http_requests",
			Help: "V=1 UNIT=ops DESC=proxied http requests by target and status (excluding rejected ones)",
		},
		[]string{"targetservice", "targethost", "statuscode", "name"},
	)
	maxReqCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "h2gproxy_total_http_requests",
			Help: "V=1 UNIT=ops DESC=proxied http requests by target and status (including rejected (e.g. too busy) ones)",
		},
		[]string{"name"},
	)
	limitGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "h2gproxy_configured_limits",
			Help: "V=1 UNIT=ops DESC=exposed the current configuration as metric for some configuration itmes",
		},
		[]string{"name", "option"},
	)
	statusCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "h2gproxy_http_status_responses",
			Help: "proxied http requests by status type",
		},
		[]string{"targetservice", "targethost", "statuscode", "name"},
	)
	inFlightGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "h2gproxy_requests_currently_in_flight",
			Help: "proxied http requests currently in flight by target and name",
		},
		[]string{"targetservice", "name"},
	)
	reqUserCounter = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "h2gproxy_http_requests_users",
			Help: "proxied http requests by target and users",
		},
		[]string{"targetservice", "targethost", "userid", "name", "statuscode"},
	)
	my_transport = &http.Transport{
		Proxy:           nil,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: false,
		}).DialContext,
		MaxIdleConnsPerHost:   5,
		DisableKeepAlives:     true,
		MaxIdleConns:          2,
		IdleConnTimeout:       10 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	authproxy *authServerProxy
)

// we have exactly one per config entry
type HTTPForwarder struct {
	def *pb.AddConfigHTTPRequest
	// result of last lookup (if addressed by servicename)
	lastHost string
	lastPort int
	server   *http.Server
	// below managed internally to throttle if necessary
	mutex            sync.RWMutex
	currentInFlights int32
	currentlyBusy    bool
	persec_idx       int32  // counter of requests per second for this second
	persec_ctr       uint32 // how many requests in the second persec_idx so far?
	isAbsolute       bool   // true for things like weblogin and acme to get priority
}

func (h *HTTPForwarder) ApiTypeName() string {
	return h.def.ApiType
}

func (hf *HTTPForwarder) IsHTTPProxy() bool {
	if hf.Api() == 0 {
		return true
	}
	return false
}

func (hf *HTTPForwarder) IsWebAPI() bool {
	if hf.Api() == 2 {
		return true
	}
	return false
}
func (hf *HTTPForwarder) IsWebSocketAPI() bool {
	if hf.Api() == 7 {
		return true
	}
	return false
}
func (hf *HTTPForwarder) IsWebloginAPI() bool {
	if hf.Api() == 3 {
		return true
	}
	return false
}
func (hf *HTTPForwarder) IsDownloadProxy() bool {
	if hf.Api() == 4 {
		return true
	}
	return false
}
func (hf *HTTPForwarder) IsFancyProxy() bool {
	if hf.Api() == 5 {
		return true
	}
	return false
}
func (hf *HTTPForwarder) IsBiStreamProxy() bool {
	if hf.Api() == 6 {
		return true
	}
	return false
}
func (hf *HTTPForwarder) IsJsonAPI() bool {
	if hf.Api() == 1 {
		return true
	}
	return false
}

// if required, redirect request to https
// if so, return true, otherwise false
// caller should abort request processing on true (because request has been redirected)
func (hf *HTTPForwarder) didHTTPSUpgrade(w http.ResponseWriter, r *http.Request) bool {
	if hf.def.AcceptHTTP {
		return false
	}
	if strings.Contains(r.Host, ":") {
		p := strings.Split(r.Host, ":")
		if len(p) == 2 {
			port, err := strconv.Atoi(p[1])
			if err != nil {
				fmt.Printf("Invalid hostname, not upgrading to https (%s): %s\n", r.Host, err)
				return false
			}
			if port != 80 {
				// any port other than 80 -> do not upgrade
				return false
			}
		}
	}
	// only upgrade those for which we actually have a certificate
	if !HaveCert(r.Host) || !*http_upgrade {
		return false
	}
	u := fmt.Sprintf("%s", r.URL)
	if strings.HasPrefix(u, "/") {
		u = strings.TrimPrefix(u, "/")
	}
	newUrl := fmt.Sprintf("https://%s/%s", r.Host, u)
	// redirect now
	//	fmt.Printf("%s upgrade %s -> %s\n", r.Proto, r.URL, newUrl)
	http.Redirect(w, r, newUrl, http.StatusMovedPermanently)
	return true
}
func (hf *HTTPForwarder) BusyInc() {
	hf.mutex.Lock()
	defer hf.mutex.Unlock()
	defer hf.updateGauge()
	hf.currentInFlights++
	hf.persec_ctr++
}
func (hf *HTTPForwarder) BusyDec() {
	hf.mutex.Lock()
	defer hf.mutex.Unlock()
	defer hf.updateGauge()
	if hf.currentInFlights == 0 {
		return
	}
	hf.currentInFlights--
}

// Update the gauge to show the current in-flight requests
func (hf *HTTPForwarder) updateGauge() {
	inFlightGauge.With(prometheus.Labels{
		"name":          hf.def.ConfigName,
		"targetservice": hf.def.TargetService,
	}).Set(float64(hf.currentInFlights))
}
func (hf *HTTPForwarder) TooBusy() bool {
	if hf.def.MaxPerSec != 0 {
		n := int32(time.Now().Unix())
		if hf.persec_idx != n {
			hf.persec_idx = n
			hf.persec_ctr = 0
		}
		if hf.persec_ctr > hf.def.MaxPerSec {
			// rate limit..
			if *debug_throttle {
				fmt.Printf("Throttled: %d of %d req/s\n", hf.persec_ctr, hf.def.MaxPerSec)
			}
			return true
		}
		// check max rate
	}
	//	hf.updateGauge() // shouldn't really be necessary, right?

	if hf.def.MaxInFlights == 0 {
		return false
	}
	lowerf := float32(hf.def.MaxInFlights)
	lowerf = lowerf * .9
	lower := int32(lowerf)

	hf.mutex.Lock()
	if hf.currentlyBusy {
		if hf.currentInFlights < lower {
			hf.currentlyBusy = false
		}
	} else {
		if hf.currentInFlights >= hf.def.MaxInFlights {
			hf.currentlyBusy = true
		}
	}
	hf.mutex.Unlock()
	return hf.currentlyBusy
}

func init() {
	prometheus.MustRegister(reqHostCounter, timsummary, reqCounter, reqCounterIn, statusCounter, inFlightGauge, reqUserCounter, maxReqCounter, limitGauge)
}

func getUserIdentifier(user *apb.User) string {
	if user == nil {
		return ""
	}
	return user.Abbrev
}

// create a new proxy and store the request and responsewrite in it
func NewProxy(w http.ResponseWriter, r *http.Request, h *HTTPForwarder, tls bool, port int) *FProxy {

	// create new fproxy
	res := &FProxy{
		port:       port,
		statusCode: 200,
	}
	// we do this as soon as we can to get accurate reading
	res.Started = time.Now()
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
	StartRequest(res)
	return res
}

// execute the request (called by the http handler)
func (f *FProxy) execute() {
	f.execute_raw()
	EndRequest(f)
}
func (f *FProxy) execute_raw() {
	reqCounterIn.With(prometheus.Labels{
		"name":          f.hf.def.ConfigName,
		"targetservice": f.hf.def.TargetService,
		"proto":         f.req.Proto,
		"targethost":    f.targetHost}).Inc()

	f.clientReqHost = f.req.Host
	reqHostCounter.With(prometheus.Labels{"host": f.req.Host, "name": f.hf.def.ConfigName}).Inc()
	NoteHost(f.clientReqHost, (f.scheme == "https"))
	if !f.hf.IsWebSocketAPI() {
		// a websocket connection _must not_ be closed
		f.req.Close = true
		f.req.Header["Connection"] = []string{"close"}
	}
	if *debug {
		fmt.Printf("%s: %s -> APIType %s\n", f.FullURL(), f.hf.def.ConfigName, f.hf.ApiTypeName())
	}

	// OPTIONS must be handled differently - they are not authenticated, but need to be replied to
	//	fmt.Printf("Method: \"%s\"\n", f.req.Method)
	if strings.ToLower(f.req.Method) == "options" {
		option_handler(f)
		return
	}

	sess, serr := f.GetSessionToken()
	if serr != nil {
		fmt.Printf("Session token cannot be retrieved: %s\n", utils.ErrorString(serr))
	}
	if *debug_session {
		fmt.Printf("Session-token: \"%s\"\n", sess)
	}
	if sess == "" && f.hf.def.SessionRequired {
		// redirect to sso to get a session
		make_browser_fetch_a_session(f)
		return
	}

	if f.hf.IsRedirectMatcher() {
		RedirectRewrite(f)
		return
	}
	if f.hf.IsJsonAPI() {
		WebProxy(f)
		//JSONProxy(f)
		return
	}
	if f.hf.IsWebAPI() {
		WebProxy(f)
		return
	}
	if f.hf.IsWebSocketAPI() {
		WebSocketProxy(f)
		return
	}
	if f.hf.IsWebloginAPI() {
		// only happens on redirects (e.g. sso.something)
		// or logout (browser goes to https://domain/weblogin/logout)
		WebLoginProxy(f)
		return
	}
	if f.hf.IsDownloadProxy() {
		DownloadProxy(f)
		processTimings(f)
		return
	}
	if f.hf.IsFancyProxy() {
		FancyProxy(f)
		return
	}
	if f.hf.IsBiStreamProxy() {
		BiStreamProxy(f)
		return
	}
	if !f.hf.IsHTTPProxy() {
		fmt.Printf("this (%s) is an unknown API type (%d)\n", f.String(), f.hf.Api())
		return
	}
	// it is an http -> http proxy thing

	// if we have a bearer token we add the useraccount
	// to the context (whether or not authentication is required or not)
	if f.unsigneduser == nil {
		a := &authResult{f: f}
		a.UserFromBearer()
		f.SetUser(a.SignedUser())
	}

	// do we actually need to proxy?
	// check if we
	// * need auth
	// * don't have a basic authentication header
	//  * and a useragent who needs basic auth
	if *enBasicAuth { // feature enabled? if not skip entire section
		if f.hf.def.NeedAuth {
			if f.unsigneduser == nil && f.needsBasicAuth() {
				if !f.doBasicAuth() {
					// not authenticated
					// we're replying with please authenticate
					return
				}
				if *debug {
					fmt.Printf("We ARE basic-authenticated as %v\n", f.userString())
				}
			}
		}
	}

	err := f.reverse_proxy_lookup(f.hf)
	if err != nil {
		f.SetError(err)
		return
	}

	// we want to check the response for 401/403 errors:
	rv := &httputil.ReverseProxy{
		Director:       f.director,
		ModifyResponse: f.responseHandler,
		Transport:      my_transport,
	}
	if *auto_flush {
		rv.FlushInterval = time.Duration(300) * time.Millisecond
	}
	f.headers_in = headersToString(f.req.Header)
	f.ReleaseResponse() // this means fproxy won't be responsible for the response. It's an error to send data through fproxy thereafter
	rv.ServeHTTP(f.writer, f.req)
	processTimings(f)

	/*
		if *debug {
			fmt.Printf("request: %v\n", f.req)
		}
	*/
	my_transport.CloseIdleConnections()
}

/****************************************************************************
* called BEFORE the request is made
* IMHO this entire function is a bit shit
* It went through a lot of iterations and got increasingly more convoluted.
* Rewriting is good - but it needs 'thinking'.
****************************************************************************/

func (f *FProxy) director(req *http.Request) {
	t := f.AddTiming("director")
	f.director2(req)
	t.Done()

}
func (f *FProxy) director2(req *http.Request) {
	var path string
	f.redirectedToWeblogin = false
	f.requested_host = req.Host
	f.remoteHost = req.RemoteAddr
	if *enable_raw_paths {
		path = req.URL.EscapedPath()
	} else {
		path = req.URL.Path
	}
	// if feature is enabled - check internal paths
	if *enable_acl_paths {
		if isInternalPath(path) && (!f.isFromRFC1918()) {
			fmt.Printf("access to %s from %s denied (only allowed from RFC1918 addresses)\n", path, f.remoteHost)
			req.URL = f.Errorurl
			req.Host = *DefaultHost
			f.SetAndLogFailure(INTERNAL_ACCESS_DENIED_EXTERNAL, fmt.Errorf("need RFC1918 address"))
			return
		}
	}
	dest_host := f.hf.def.TargetHost
	dest_port := int(f.hf.def.TargetPort)
	if *debug {
		fmt.Printf("Request matching %s\n", f.hf.GetID())
	}

	// work out where to send it to
	if f.hf.def.TargetService != "" {
		err := f.reverse_proxy_lookup(f.hf)
		if err != nil {
			fmt.Printf("Failed to lookup targetservice %s for path %s: %s\n", f.hf.def.TargetService, path, err)
			req.URL = f.Errorurl
			req.Host = *DefaultHost
			f.SetAndLogFailure(INTERNAL_ERROR_NO_TARGET, err)
			return
		}
		dest_host = f.hf.lastHost
		dest_port = f.hf.lastPort
	}
	var err error
	// check if our target needs authentication
	// if so -> redirect it to weblogin (the logintarget)
	if (f.hf.def.NeedAuth) && (f.unsigneduser == nil) {
		if *debug {
			fmt.Printf("need user, authenticating in http-proxy")
		}
		if *stdauth {
			f.authResult, err = json_auth(f)
			f.SetUser(f.authResult.SignedUser())
		} else {
			var c *http.Cookie
			c, err = f.req.Cookie(COOKIE_NAME)
			if err == nil {
				f.SetUser(GetUserFromCookie(c))
			}
		}
		if err != nil || f.unsigneduser == nil {
			if *debug {
				fmt.Printf("No auth cookie - redirecting to login (err=%s)\n", err)
			}
			err := f.reverse_proxy_lookup(loginTarget) // sets 'lasthost'
			if err != nil {
				fmt.Printf("Failed to lookup loginservice %s for path %s: %s\n", f.hf.def.TargetService, path, err)
				req.URL = f.Errorurl
				req.Host = *DefaultHost
				f.SetAndLogFailure(INTERNAL_ERROR_NO_LOGIN_BACKEND, err)
				return
			}
			// set the stuff the weblogin thing needs:
			req.Header.Set("X-Requested-Method", req.Method)
			req.Header.Set("X-Requested-Scheme", f.scheme)
			req.Header.Set("X-Requested-Host", req.Host)
			req.Header.Set("X-Requested-Location", req.URL.Path)
			req.Header.Set("X-Requested-Query", req.URL.RawQuery)
			dest_host = loginTarget.lastHost
			dest_port = loginTarget.lastPort
			f.redirectedToWeblogin = true
		}

		f.loginProxy = true
	}

	// and... one more check. check if the user is valid!
	if (f.hf.def.NeedAuth) && (f.unsigneduser != nil) {
		if !f.unsigneduser.EmailVerified {
			// user email not verified
			fmt.Printf("User %v email is not (yet) verified (path=%s)\n", f.unsigneduser, path)
			req.URL = f.Errorurl
			req.Host = *DefaultHost
			f.SetAndLogFailure(INTERNAL_ACCESS_DENIED_EMAILVERIFY, fmt.Errorf("user email not verified"))
			return
		}
	}

	// and... one more check. If our target definition includes groups,
	// we verify that the logged in user is really in one of the groups
	if (f.hf.def.NeedAuth) && (f.unsigneduser != nil) && len(f.hf.def.Groups) > 0 {
		if !isUserInGroup(f.unsigneduser, f.hf.def.Groups) {
			// oooh is not.
			fmt.Printf("User %v is not in any of the groups for path %s\n", f.unsigneduser, path)
			req.URL = f.Errorurl
			req.Host = *DefaultHost
			f.SetAndLogFailure(INTERNAL_ACCESS_DENIED_GROUP, fmt.Errorf("internal_access_denied_group"))
			return
		}
	}

	// now we know our target -> build the url
	// we want to redirect to dest_host and dest_target
	// (this could be a 'real' backend or our weblogin or a legacy application

	// here we build the URL we're passing to the backend.
	// it's a bit funny, we strip away what we matched on, then add the pathprefix again
	// that's because legacy applications like to be addressed at the root path
	// so initially I'd been thinking that it makes sense to remove the path, now I don't think it does
	// it's the exception not the default. It makes it hard to understand the configuration

	// build the new URL: (add parameters, except the urlsnippet)
	if len(path) < len(f.hf.def.URLPath) {
		fmt.Printf("Should not happen (path=%s,urlpath=%s)!!\n", path, f.hf.def.URLPath)
		req.URL = f.Errorurl
		req.Host = *DefaultHost
		f.SetAndLogFailure(INTERNAL_ERROR_BUG, fmt.Errorf("internal error: urlpath is off"))
		return
	}
	// strip out the urlpath (the stuff we matched on)
	npath := path[len(f.hf.def.URLPath):]
	// now add the pathprefix
	if f.hf.def.PathPrefix != "" {
		deli := "/"
		if strings.HasSuffix(f.hf.def.PathPrefix, "/") || (strings.HasPrefix(npath, "/")) {
			deli = ""
		}
		npath = fmt.Sprintf("%s%s%s", f.hf.def.PathPrefix, deli, npath)
	}
	//fmt.Printf("requestpath: \"%s\" -> \"%s\"\n", path, npath)
	q := ""
	if req.URL.RawQuery != "" {
		q = fmt.Sprintf("?%s", req.URL.RawQuery)
	}
	hs := buildHostPortPath(dest_host, dest_port)
	if (len(npath) > 0) && (npath[:1] != "/") {
		npath = fmt.Sprintf("/%s", npath)
	}
	if strings.HasSuffix(npath, "//") {
		npath = npath[:len(npath)-1]
	}
	if *debugRewrite {
		fmt.Printf("URL: %s\n", req.URL.String())
	}
	us := fmt.Sprintf("http://%s%s%s", hs, npath, q)
	if f.hf.def.TargetPort == 443 || f.hf.def.ProxyForHTTPS {
		us = fmt.Sprintf("https://%s%s%s", hs, npath, q)
	}

	if *debugRewrite {
		fmt.Printf("hs=\"%s\", npath=\"%s\", q=\"%s\", us=%s, pathprefix=%s\n", hs, npath, q, us, f.hf.def.PathPrefix)
	}

	u, err := url.Parse(us)
	if err != nil {
		fmt.Printf("WTF?? %s encountered url parse error: %s\n", us, err)
		req.Host = *DefaultHost
		req.URL = f.Errorurl
		f.SetAndLogFailure(INTERNAL_ERROR_CONFIG_ERROR, err)
		return
	}

	// so we now done the url building bit and got the url in 'u'

	req.URL = u
	req.Host = dest_host

	// add extra headers here
	if f.hf.def.TargetHostname != "" {
		if *debug {
			fmt.Printf("Setting hostname to custom targethostname: %s\n", f.hf.def.TargetHostname)
		}
		s := f.hf.def.TargetHostname
		if s == "donttouch" {
			_, b, c := splitHostStuff(f.requested_host)
			s = b
			if c != "" {
				s = fmt.Sprintf("%s:%s", b, c)
			}
		}
		req.Header.Set("Host", s)
		req.Host = s
	} else {
		req.Host = dest_host
		req.Header.Set("Host", dest_host)
	}
	req.Header.Set("Stuff", "moo.trace") // because we can? :)
	f.targetHost = dest_host

	// also add the context BEFORE we call the backend so we have requestid and user stuff
	// to set in the headers
	f.AddContext()

	if *logrequests {
		fmt.Printf("%s: Forwarding \"%s\",path=\"%s\" to url=\"%s\" on %s (Host-Header:%s) (Forwarded-Host: %s) for user %s\n", req.RemoteAddr, f.clientReqHost, path, req.URL.Path, req.Host, req.Header["Host"], f.hf.def.ForwardedHost, f.currentUser())
	}
	// if we have a user we set headers telling the backend about it
	if f.unsigneduser != nil {
		// set headers
		AddUserIDHeaders(f, req)
		// some backends (e.g. gerrit) like to store passwords and need this header
		// we always send the same password ('stuff') because we control access to the backend
		// ourselves
		if f.hf.def.SendFakeAuthorization {
			s := f.unsigneduser.ID
			if f.hf.def.UserNameForFakeAuth == "email" {
				s = f.unsigneduser.Email
			} else if f.hf.def.UserNameForFakeAuth == "abbrev" {
				s = f.unsigneduser.Abbrev
			}
			req.Header.Set("Authorization", createAuthHeader(s))
		}
	} else {
		if f.hf.def.SendFakeAuthorization {
			if *debug {
				fmt.Printf("Warning - we're supposed to send fake auth but user is not authenticated\n")
			}
		}

		// clear any user headers submitted previously by the user
		req.Header.Del("REMOTE_USER")
		req.Header.Del("REMOTE_USERID")
		if (!f.hf.def.AllowAuthorizationFromClient) && (!f.needsBasicAuth()) {
			// we need this header, it's the response to a basicauth
			req.Header.Del("Authorization")
		}
	}

	// explicitly pass in the requests as in 1.11 a new header object will be created within httputils.reverseproxy(....)
	stripHeadersToBackend(req)
	// add automatic headers e.g. X-Forwarded-for
	setForwardedHeaders(f, req)
	// add user specified headers
	addHeaders(f, req)
	f.headers_to_backend = headersToString(req.Header)
	if *logrequests && *debug {
		fmt.Printf("%s: req.Host=\"%s\", req.Header[Host]=\"%s\" (clientrequest: %s) method:%s\n", req.RemoteAddr, req.Host, req.Header["Host"], f.requested_host, req.Method)
	}
	if *debugRewrite {
		fmt.Printf("asking backend for %s %s\n", req.Method, req.URL)
	}

}

/****************************************************************************
// called AFTER the response comes back from the backend
****************************************************************************/

func (f *FProxy) responseHandler(resp *http.Response) error {
	tx := f.AddTiming("response")
	xerr := f.responseHandler2(resp)
	tx.Done()
	if xerr != nil {
		fmt.Printf("err: %s ", xerr)
		for _, t := range f.Timings {
			dur := t.start.Sub(t.end) / time.Millisecond
			fmt.Printf("%s=%d ", t.name, dur)
		}
		fmt.Println()
	}
	return xerr
}
func (f *FProxy) responseHandler2(resp *http.Response) (err error) {
	if *debug {
		fmt.Printf("proxy response handler started\n")
	}
	f.AddContext()
	f.proxyResponse = resp
	f.headers_out = headersToString(f.req.Header)
	f.headers_received = headersToString(resp.Header)
	if *printHeaders {
		fmt.Printf("Headers from browser: %s\n", f.headers_in)
		fmt.Printf("Headers to backend: %s\n", f.headers_to_backend)
		fmt.Printf("Headers from backend (%d): %s\n", resp.StatusCode, f.headers_received)
		fmt.Printf("Headers to browser (%s): %s\n", f.req.URL, f.headers_out)
	}
	// we are leaking file descriptors.
	// it's the incoming TCP Connection which doesn't get closed ;(
	// below leads to cancelled contexts
	//resp.Close = true
	// can't do this: proxy gets unhappy
	//_, err = ioutil.ReadAll(resp.Body)
	/*
		if err == nil {
			resp.Body.Close()
		}
	*/
	// this breaks it:
	//resp.Body.Close()

	host := resp.Request.Host
	ph, ps, err := net.SplitHostPort(resp.Request.URL.Host)
	if err != nil && *debug {
		fmt.Printf("Weird response url: %s\n", resp.Request.URL.Host)
	}
	if *debug {
		fmt.Printf("Response target: %s %s\n", resp.Request.Method, resp.Request.URL)
	}
	port, err := strconv.Atoi(ps)
	if err != nil {
		if *debug {
			fmt.Printf("Weird port part in response url: %s (%s)\n", resp.Request.URL.Host, ps)
		}
		port = 80
	}
	if host == "" {
		host = ph
	}
	f.SetStatus(resp.StatusCode)

	//	elapsed := time.Now().Sub(f.Started)
	//	ms := elapsed.Nanoseconds() / 1000 / 1000
	f.ResponseTime = time.Since(f.Started)

	f.LogResponse()
	f.customHeaders(&ExtraInfo{})

	if (resp.StatusCode >= 200) && (resp.StatusCode <= 299) {
		// all is good
		return nil
	}
	if *enBasicAuth {
		if f.loginProxy {
			if *debug {
				fmt.Printf("Login-Response from \"%s:%d\": %03d\n", host, port, resp.StatusCode)
			}
			return nil
		}
	}
	if *debug {
		fmt.Printf("Response from \"%s:%d\": %03d\n", host, port, resp.StatusCode)
	}
	// this is a bit unexpected:
	// if our proxy is configured to authenticate, this shouldn't really happen.
	// it's here in case legacy applications insist on doing their own authentication.
	// we intercept 401 codes from the backend and instead redirect our client to /login
	// we assume that once client logs in via /login the next time we hit this URL we'll be
	// sending a REMOTE_USER header and the backend should be happy
	//
	// check the h2gproxy yaml configuration - there is probably a 'needauth: true' missing
	// for this url
	//
	if resp.StatusCode == 401 {
		if f.hf.def.WebBackendAuthenticatesOnly {
			if *debug {
				fmt.Printf("Passing 401 to client application (%v)\n", f.req.URL)
			}
			return
		}
		if f.hf.def.NeedAuth {
			fmt.Printf("Statuscode: 401 found in response to %v AND we got needauth=true in config [user #%s, %s]!\n", f.req.URL, f.unsigneduser.ID, f.unsigneduser.Email)
			resp.StatusCode = 501
			return nil
		} else {
			if f.hf.def.AllowAuthorizationFromClient || f.needsBasicAuth() {
				if *debug {
					fmt.Printf("Passing 401 to client application (%v)\n", f.req.URL)
				}
				return
			}
			fmt.Printf("Statuscode: 401 found in response to %v. needauth:true missing in config?\n", f.req.URL)
		}
		resp.StatusCode = http.StatusTemporaryRedirect
		// the http backend send a 401. Send the browser to sso.yacloud.eu (with current path)...
		target := webloginGetRedirectTarget(f)
		if *debug_redirect {
			fmt.Printf("due to 401: redirecting to: \"%s\"\n", target)
		}
		resp.Header["Location"] = []string{target}
		f.SetStatus(resp.StatusCode) // for the logs...
		return nil
	}

	if (resp.StatusCode == 302) || (resp.StatusCode == 301) || (resp.StatusCode == 307) {
		// it's a flipping redirect
		newLocations := resp.Header["Location"]
		if len(newLocations) < 1 {
			resp.StatusCode = 501
			f.createErrorPage(resp)
			return nil
		}
		newLocation := newLocations[0]
		if *debug_redirect {
			fmt.Printf("Redirect To: %s (rewriteredirecthost=%v)\n", newLocation, f.hf.def.RewriteRedirectHost)
		}
		if f.hf.def.RewriteRedirectHost {
			verynewLocation := f.FixRedirect(newLocation)
			if *debug_redirect {
				fmt.Printf("backend redirected to %s - we redirect client to %s instead\n", newLocation, verynewLocation)
			}
			resp.Header.Set("Location", verynewLocation)
		}
	}
	if resp.StatusCode >= 400 {
		if *debug {
			fmt.Printf("Statuscode: %d\n", resp.StatusCode)
		}
	}
	if (resp.StatusCode >= 500) && (f.hf.def.ErrorPage500 != "") {
		f.createErrorPage(resp)
	}

	return nil
}

// inject a fake user header
func createAuthHeader(userid string) string {
	s := fmt.Sprintf("%s:%s", userid, "Rai3ig0loeh2")
	s = b64.StdEncoding.EncodeToString([]byte(s))
	s = fmt.Sprintf("Basic %s", s)
	return s
}

// return a normalized string of the status code
// e.g. 1xx(Informational) or 4xx(Client Error)
func normalizeStatusCode(code int) string {
	if code < 100 {
		return fmt.Sprintf("%d(Invalid)", code)
	}
	if code < 200 {
		return "1xx(Informational)"
	}
	if code < 300 {
		return "2xx(Success)"
	}
	if code < 400 {
		return "3xx(Redirect)"
	}
	if code < 500 {
		return "4xx(Client error)"
	}
	if code < 600 {
		return "5xx(Server error)"
	}
	return fmt.Sprintf("%d(Invalid)", code)
}

// request has been made, we log the response
func (f *FProxy) LogResponse() {
	if *debug {
		fmt.Printf("Responded to forwarding %s to %s: %d\n", f.hf.def.TargetService, f.targetHost, f.statusCode)
	}
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
	reqUserCounter.With(prometheus.Labels{
		"name":          f.hf.def.ConfigName,
		"targetservice": f.hf.def.TargetService,
		"statuscode":    normalizeStatusCode(f.statusCode),
		"targethost":    f.targetHost,
		"userid":        getUserIdentifier(f.unsigneduser)}).Inc()
	if *add_hist {
		f.ObserveTiming(f.ResponseTime)
	}
	var err error
	/*
		ph, _, err := net.SplitHostPort(f.remoteHost)
		if err != nil {
			ph = f.remoteHost
		}
		ncr := hpb.NewCallRequest{}
		ncr.Service = f.hf.def.TargetService
		ncr.TargetHost = f.targetHost
		ncr.RemoteHost = ph
		ncr.RequestURL = f.req.URL.String()
		ncr.ResponseCode = int32(f.statusCode)
		ncr.ResponseTimeMS = int64(f.ResponseTime.Milliseconds())
		ncr.Group = f.hf.def.ConfigName
		if !f.redirectedToWeblogin {
			ncr.Group = f.hf.def.ConfigName
			if f.unsigneduser != nil {
				ncr.UserID = f.unsigneduser.ID
			}
		} else {
			ncr.Group = "weblogin"
		}
		logQ.LogHTTP(&ncr)
	*/
	f.logreq.RequestFinished(uint32(f.statusCode), f.hf.def.TargetService, "", f.err)
	f.AddContext()

	if *logusage {
		_, err = usageStatsClient.LogHttpCall(f.Context(), &us.LogHttpCallRequest{
			Url:       f.req.URL.String(),
			Success:   true,
			Timestamp: uint32(f.Started.Unix()),
		})

		if err != nil {
			fmt.Printf("successfull backend call: failed to update usage stats %s\n", utils.ErrorString(err))
		}

	}
}
func addHeaders(f *FProxy, req *http.Request) {
	for _, header := range f.hf.def.Header {
		hs := strings.SplitN(header, "=", 2)
		if len(hs) < 2 {
			fmt.Printf("Invalid header definition: \"%s\"\n", header)
			continue
		}
		key := hs[0]
		value := hs[1]
		if *debug {
			fmt.Printf("   Adding Header: %s:%s\n", key, value)
		}
		req.Header.Set(key, value)
	}
}

// add http headers to the backend
// X-Forwarded-For: client-ip
// X-Forwarded-Host: original host requested by the client
func setForwardedHeaders(f *FProxy, req *http.Request) {
	if *enable_raw_paths {
		req.Header.Set("X-Forwarded-Path", f.req.URL.EscapedPath())
	} else {
		req.Header.Set("X-Forwarded-Path", f.req.URL.Path)
	}
	if f.hf.def.ForwardedHost == "" {
		req.Header.Set("X-Forwarded-Host", f.clientReqHost)
	} else if f.hf.def.ForwardedHost == "targethost" {
		req.Header.Set("X-Forwarded-Host", f.hf.def.TargetHost)
	} else {
		req.Header.Set("X-Forwarded-Host", f.hf.def.ForwardedHost)
	}

	req.Header.Set("REMOTE_HOST", f.remoteHost)
	req.Header.Set("REMOTE_ADDR", f.PeerIP())
	req.Header.Set("X-LB-REQUESTID", f.GetRequestID())
	req.Header.Set("X-Forwarded-Proto", f.scheme)
	//ff := f.req.Host
	if f.hf.def.ForwardedFor == "" {
		return
	}

	if f.hf.def.ForwardedFor == "ip" {
		req.Header.Set("X-Forwarded-For", f.req.Host)
	} else if f.hf.def.ForwardedFor == "targethost" {
		req.Header.Set("X-Forwarded-For", f.targetHost)
	} else if f.hf.def.ForwardedFor == "donttouch" {
		// f.req.Header.Set("X-Forwarded-For", ff)
	} else if f.hf.def.ForwardedFor != "" {
		req.Header.Set("X-Forwarded-For", f.hf.def.ForwardedFor)
	}

}

func headersToString(header http.Header) string {
	res := ""
	for k, vs := range header {
		for _, v := range vs {
			res = fmt.Sprintf("%s\n   %s:%s", res, k, v)
		}
	}
	return fmt.Sprintf("%s\n", res)
}

func (f *FProxy) createErrorPage(resp *http.Response) (err error) {

	fmt.Printf("Statuscode %d intercepted whilst serving %s\n", resp.StatusCode, f.req.URL.String())
	s := "An error was encountered. Sorry about that."
	body := ioutil.NopCloser(strings.NewReader(s))
	resp.StatusCode = 200
	resp.Body = body
	resp.ContentLength = int64(len(s))
	resp.Header.Set("Content-Length", strconv.Itoa(len(s)))
	return nil
}

/**********************************
* implementing basic auth
***********************************/

func (f *FProxy) doBasicAuth() bool {
	if !*enBasicAuth {
		return false
	}
	// check if browser sent us an authenticate thingie
	u, p, gotit := f.req.BasicAuth()
	if gotit {
		a, xerr := f.authenticateUser(u, p)
		if xerr != nil {
			fmt.Printf("Failed to authenticate: %s\n", utils.ErrorString(xerr))
		}
		if a != nil {
			// auth ok
			f.SetUser(a)
			return true
		}
		if *debug { // NOT A DEBUG IF CLAUSE
			if a != nil {
				fmt.Printf("BasicAuthed() user #%s(%s)\n", f.unsigneduser.ID, f.unsigneduser.Email)
			} else {
				fmt.Printf("Failed to verify unknown user's identity with basicauth\n")
			}
		}
	}
	//	fmt.Printf("Requesting login via 401 code\n")
	f.SetHeader("WWW-Authenticate", "Basic realm=\"Login\"")
	f.SetStatus(401)
	return false
}

func (f *FProxy) needsBasicAuth() bool {
	r := f.req
	if !*enBasicAuth {
		return false
	}
	if f.hf.def.ForceBackendAuthorization {
		return true
	}
	if f.hf.def.DisableFormBasedAuth {
		return true
	}
	s := r.Header.Get("User-Agent")
	/*
		if strings.Contains(s, "Go-http-client") {
			return true
		}
	*/
	for _, k := range known_cli_download_tools {
		if strings.HasPrefix(s, k) {
			return true
		}
	}
	return *basicAuth
}

func (hf *HTTPForwarder) String() string {
	if hf.def == nil {
		return "[emptydef]"
	}
	return hf.GetID()
}
func (hf *HTTPForwarder) GetID() string {
	s := hf.def.URLHostname
	if s == "" {
		s = "any"

	}
	return fmt.Sprintf("%s:%s for host \"%s\"", hf.def.ConfigName, hf.def.URLPath, s)
}

// given an arbitrary string, should replace
// any non valid characters with _
// valid chars are a-z0-9A-Z
func escapeMetric(old string) string {
	var buffer bytes.Buffer
	n := false
	for _, c := range old {
		b := '_'
		if isValidMetricChar(c) {
			b = c
			n = true
		}
		if n {
			buffer.WriteRune(b)
		}
	}
	return buffer.String()
}
func isValidMetricChar(x rune) bool {
	valid := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for _, v := range valid {
		if v == x {
			return true
		}
	}
	return false
}

// return true if it contains things like /metrics/ or /internal/
func isInternalPath(path string) bool {
	if strings.Contains(path, "/metrics/") {
		return true
	}
	if strings.Contains(path, "/internal/") {
		return true
	}
	return false
}

// return true if the request comes from a 'private' ip
func (f *FProxy) isFromRFC1918() bool {
	ip := f.req.RemoteAddr
	return isPrivateIP(ip)
}
func isPrivateIP(ip string) bool {
	// do a quick stringmatch...
	if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") {
		return true
	}
	if !strings.HasPrefix(ip, "172.") {
		return false
	}
	// strings was inconclusive - look closely at the ip
	private := false
	if strings.Contains(ip, ":") {
		ip = ip[:strings.LastIndex(ip, ":")]
	}
	IP := net.ParseIP(ip)
	if IP == nil {
		return false // not an ip we can parse, so it's not "private"
	}

	// for speed, we probably want to make this static...
	_, private24BitBlock, _ := net.ParseCIDR("10.0.0.0/8")
	_, private20BitBlock, _ := net.ParseCIDR("172.16.0.0/12")
	_, private16BitBlock, _ := net.ParseCIDR("192.168.0.0/16")
	private = private24BitBlock.Contains(IP) || private20BitBlock.Contains(IP) || private16BitBlock.Contains(IP)

	return private
}

func isUserInGroup(user *apb.User, groups []string) bool {
	if (len(groups) != 0) && (len(user.Groups) == 0) {
		if *debug_groups {
			fmt.Printf("User is in no groups, but match requires groups!\n")
		}
		return false
	}
	for _, rg := range groups {
		if auth.IsInGroupByUser(user, rg) {
			return true
		}
	}
	return false
}

// splits https://foo:80 into https,foo,80
// splits https://foo into https,foo,""
// splits foo:80 into "",foo,80
// splits foo into "",foo,""
func splitHostStuff(s string) (string, string, string) {
	st := strings.Split(s, ":")
	if len(st) == 3 {
		return st[0], strings.TrimPrefix(st[1], "//"), st[2]
	}
	if len(st) == 2 {
		// https://foo ?
		if strings.HasPrefix(st[1], "//") {
			return st[0], strings.TrimPrefix(st[1], "//"), ""
		}
		return "", st[0], st[1]
	}
	return "", s, ""
}

// given a string url will rewrite the host/port/scheme part to match the inbound request
func (f *FProxy) FixRedirect(s string) string {

	_, b, c := splitHostStuff(f.requested_host)
	nhost := f.scheme + "://" + b
	if c != "" {
		nhost = fmt.Sprintf("%s://%s:%s", f.scheme, b, c)
	}

	// url is always fqdn (says RFC)
	// so it's https://foobar/stuff
	// or it's https://foobar:80/stuff
	// or it's http://foobar
	// or it's https://foobar:80

	// remove scheme:
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	i := strings.Index(s, "/")
	if i == -1 {
		return "cnw://foobar"
	}
	s = s[i:]
	return nhost + s
}

// remove headers we DO NOT want to send to the backend ever
func stripHeadersToBackend(req *http.Request) {
	req.Header.Del("Upgrade-Insecure-Requests") // h2gproxy (must) handle(s) this
	req.Header.Del("Accept-Encoding")           // not up to the backend to decide

}

// might be empty string!
func (f *FProxy) currentUser() string {
	un := ""
	if f.unsigneduser != nil {
		un = f.unsigneduser.Abbrev
		if un == "" {
			un = f.unsigneduser.Email
		}
	}
	return un
}

// add the context and requestids stuff (calling rpcinterceptor)
func (f *FProxy) AddContext() {
	if f.unsigneduser == nil || f.ctx != nil {
		if *debug {
			fmt.Printf("[debug] no context - no user for request %s\n", f.req.URL.String())
		}
		return
	}
	err := f.rebuildContextFromScratch(f.authResult)
	if err != nil {
		fmt.Printf("no context available for user %s (%s)\n", f.unsigneduser, err)
	}

}
func (f *FProxy) Context() context.Context {
	if f.ctx != nil {
		return f.ctx
	}
	return createBootstrapContext()
}

func AddUserIDHeaders(f *FProxy, req *http.Request) {
	ms, err := f.createUserHeaders()
	if err != nil {
		fmt.Printf("Unable to insert user headers: %s\n", utils.ErrorString(err))
		return
	}
	for k, v := range ms {
		req.Header.Set(k, v)
	}

}
