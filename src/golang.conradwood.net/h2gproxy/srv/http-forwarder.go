package srv

// http parsing and request intercept
// determines where to send it
// and passes it off to http-proxy

import (
	"context"
	"flag"
	"fmt"
	pb "golang.conradwood.net/apis/h2gproxy"
	rpb "golang.conradwood.net/apis/registry"
	"golang.conradwood.net/go-easyops/client"
	"golang.conradwood.net/go-easyops/errors"
	"golang.conradwood.net/go-easyops/prometheus"
	"golang.conradwood.net/go-easyops/utils"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	COOKIE_NAME = "Auth-Token"
	WEBLOGIN    = "weblogin.Weblogin"
	ACMESERVICE = "certmanager.CertManager"
)

var (
	http_upgrade = flag.Bool("http_upgrade", true, "upgrade http requests to https if a valid certificate is available for the requested host")
	// the routes to apply to incoming requests
	routeLock          = sync.Mutex{}
	routes             []*HTTPForwarder
	httpport           = flag.String("http_port", "1080", "The port to start the HTTP listener on. multiple ports may be comma-delimited")
	debug_match        = flag.Bool("debug_match", false, "true to debug the matching of requests")
	debug_lookup       = flag.Bool("debug_lookup", false, "true to debug the lookup of targets for requests")
	http_read_timeout  = flag.Int("http_read_timeout", 90, "golang http.Server read timeout in seconds")
	http_write_timeout = flag.Int("http_write_timeout", 90, "golang http.Server write timeout in seconds")
	loginTarget        *HTTPForwarder
	rcl                rpb.RegistryClient
	gotRegistryClient  = false
)

func (r *HTTPForwarder) Stop() error {
	if r.server != nil {
		err := r.server.Shutdown(nil)
		if err != nil {
			fmt.Printf("HTTP Server shutdown failed: %s.\n", err)
		} else {
			fmt.Printf("HTTP Server shutdown.\n")
		}
		return err
	}
	return nil
}

func SetHTTPRoutes(r []*HTTPForwarder) error {
	routeLock.Lock()
	defer routeLock.Unlock()
	routes = r
	// update gauges
	for _, hf := range r {
		limitGauge.With(prometheus.Labels{"name": hf.def.ConfigName, "option": "maxpersec"}).Set(float64(hf.def.MaxPerSec))
		limitGauge.With(prometheus.Labels{"name": hf.def.ConfigName, "option": "maxinflights"}).Set(float64(hf.def.MaxInFlights))
	}
	return nil
}

func StartHTTPServer() error {
	if *httpport == "" {
		return errors.InvalidArgs(context.Background(), "config error", "refusing to start http server without port")
	}
	ld := &pb.AddConfigHTTPRequest{
		TargetService: WEBLOGIN,
		ConfigName:    "weblogin",
	}
	loginTarget = &HTTPForwarder{def: ld}

	for _, port := range portsFromString(*httpport) {
		adr := fmt.Sprintf(":%d", port)
		fmt.Printf("Starting http server on port %s\n", adr)
		er := startHTTP(loginTarget, adr, port)
		if er == nil {
			fmt.Printf("HTTP server started.\n")
		} else {
			return er
		}
	}
	go func() {
		rcl = rpb.NewRegistryClient(client.Connect("registry.Registry"))
		gotRegistryClient = true
	}()

	return nil
}

func portsFromString(ports string) []int {
	var res []int
	for _, s := range strings.Split(ports, ",") {
		p, err := strconv.Atoi(s)
		if err != nil {
			panic(fmt.Sprintf("In portlist \"%s\": %s", ports, err))
		}
		res = append(res, p)
	}
	return res
}

// silly function to check startup of http
func startHTTP(r *HTTPForwarder, adr string, port int) error {
	go func() {
		for { // it's a loop, h2gproxy is so important, we'll really try to start it
			httpMux := http.NewServeMux()
			f := &foohandler{port: port}
			httpMux.HandleFunc("/", f.handler)
			server := &http.Server{
				ReadTimeout:  time.Duration(*http_read_timeout) * time.Second,
				WriteTimeout: time.Duration(*http_write_timeout) * time.Second,
				Addr:         adr,
			}
			//		server.Handler = httpMux
			server.Handler = f
			err := server.ListenAndServe()
			fmt.Printf("Failed to start http listener: %s\n", err)
			time.Sleep(1 * time.Second)
		}
	}()
	return nil

}

type foohandler struct {
	port int
}

func (f *foohandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.handler(w, r)
}

// http-only handler - we upgrade to https if we have a matching certificate
func (f *foohandler) handler(w http.ResponseWriter, r *http.Request) {
	if r.Host == "" {
		http.Error(w, "no host", 500)
		fmt.Printf("No host specified\n")
		return
	}
	main_handler(w, r, false, f.port)
}

/********************************************************
* every request comes in here from the http.Handler
********************************************************/
func main_handler(w http.ResponseWriter, r *http.Request, isTLS bool, port int) {
	started := time.Now()
	httpproto := "http"
	if isTLS {
		httpproto = "https"
	}
	if AntiDOS_HTTPHandler(w, r, port) {
		return
	}
	hf := findBestMatch(r, httpproto)
	if hf == nil {
		w.Header().Add("Content-Type", "text/html")
		fmt.Fprintf(w, "We have no content to serve at this URL. Sorry.")
		fmt.Printf("I got %d routes:\n", len(routes))
		routeLock.Lock()
		defer routeLock.Unlock()
		for _, r := range routes {
			fmt.Printf("Route: %v\n", r.def)
		}
		fmt.Printf("No route for this request: %s (looking for prefix=\"%s\")\n", r.URL, r.URL.String())
		return
	}
	// check if we redirect this to https
	if !isTLS {
		if hf.didHTTPSUpgrade(w, r) {
			return
		}
	}

	maxReqCounter.With(prometheus.Labels{"name": hf.def.ConfigName}).Inc()

	//	fmt.Printf("Best route: %v (%v)\n", s, hf.def)
	// now create the reverse proxy for this request
	hf.BusyInc()
	defer hf.BusyDec()
	if hf.TooBusy() {
		reqCounter.With(prometheus.Labels{
			"name":          hf.def.ConfigName,
			"targetservice": hf.def.TargetService,
			"statuscode":    "429",
			"targethost":    hf.def.TargetHostname}).Inc()

		//w.Header().Add("Content-Type", "text/html")
		//fmt.Fprintf(w, "Server too busy. Please try again later")
		http.Error(w, "Server too busy", 429)
		return
	}
	errorurl, err := url.Parse(fmt.Sprintf("http://%s/errorpage.html", *DefaultHost))
	if err != nil {
		fmt.Printf("Failed to parse error url. This is bad, we cannot display errors\n")
		return
	}

	if r.ProtoMajor < 2 {
		// This will close the connection after the response is sent, but only for
		// HTTP/1 clients. We can't do this for HTTP/2 clients because the "Connection"
		// header is not valid in the HTTP/2 standard.
		//
		// That means, if we need a similar approach for HTTP/2, we'll have to find
		// another way of doing it - and https://github.com/golang/go/issues/20977 suggests
		// that there's no such way, at least as of Golang 1.10.
		w.Header().Set("Connection", "close")
	}

	//Debug: List open file descriptors for debug purpose only. Disabled by default.
	PrintOpenFDs()
	r.Close = true
	f := NewProxy(w, r, hf, isTLS, port)
	if f == nil {
		return
	}
	f.Errorurl = errorurl
	f.execute()
	f.Close()
	es := ""
	if f.statusCode < 200 || f.statusCode >= 400 {
		if f.err != nil {
			es = " (" + utils.ErrorString(f.err) + ")"
		}
	}

	user := ""
	if f.unsigneduser != nil {
		user = "/" + f.unsigneduser.Abbrev
	}

	cfgname := "nocfg"
	if f.hf != nil && f.hf.def != nil && f.hf.def.ConfigName != "" {
		cfgname = f.hf.def.ConfigName
	}
	timing := fmt.Sprintf("%0.2fs", time.Since(started).Seconds())
	fmt.Printf("[%s%s] %s %s %d %s%s\n", f.req.RemoteAddr, user, cfgname, timing, f.statusCode, f.FullURL(), es)
	//Debug: List open file descriptors. Disabled by default.
	PrintOpenFDs()

}

// this sets lasthost & lastport to the target service (or static config)
// this looks up arbitrary targets, not just the configured one, but also, say weblogin or so
func (f *FProxy) reverse_proxy_lookup(hf *HTTPForwarder) error {

	// delayed initialisation, return error if we're too early
	if !gotRegistryClient {
		return fmt.Errorf("RegistryClient unavailable")
	}

	// terrible. but the jsonapi authentication and the web authentication are
	// closely related and share codepaths.
	// it is probably worth doing another rethink which parts are shared and how
	// that can be achieved given that they are within a single request/http/tcp connection
	// this is only here to prevent the lookup from returning an error if it's been invoked
	// half-way through the json-proxy (because it needs auth)
	if hf.IsJsonAPI() {
		return nil
	}
	if hf.def.TargetHost != "" {
		hf.lastHost = hf.def.TargetHost
		hf.lastPort = int(hf.def.TargetPort)
		return nil
	}
	servicepath := hf.def.TargetService
	if servicepath == "" {
		fmt.Printf("Servicepath of \"%s\" is empty!\n", hf.def.String())
		return errors.Unavailable(context.Background(), "server misconfiguration - try later")
	}
	gt := &rpb.V2GetTargetRequest{ServiceName: []string{servicepath}, ApiType: rpb.Apitype_html}
	lr, err := rcl.V2GetTarget(context.Background(), gt)
	if err != nil {
		s := fmt.Sprintf("Error getting target for path %s: %s", servicepath, err)
		fmt.Println(s)
		return errors.Unavailable(context.Background(), fmt.Sprintf("HTTP registration for \"%s\"", servicepath))
	}
	if len(lr.Targets) == 0 {
		s := fmt.Sprintf("No html target found for path \"%s\"", servicepath)
		fmt.Println(s)
		return errors.Unavailable(context.Background(), fmt.Sprintf("HTTP registration for \"%s\"", servicepath))
	}
	var target *rpb.Target
	var no_user_target *rpb.Target
	if *debug_lookup {
		fmt.Printf("Selecting target for %s for User: %s (from %d potential targets)\n", servicepath, f.userString(), len(lr.Targets))
	}
	for _, t := range lr.Targets {
		if t.RoutingInfo == nil || t.RoutingInfo.RunningAs == nil {
			no_user_target = t
		}
		if f.unsigneduser == nil && (t.RoutingInfo == nil || t.RoutingInfo.RunningAs == nil) {
			target = t
			break
		}
		if f.unsigneduser != nil && t.RoutingInfo != nil && t.RoutingInfo.RunningAs != nil && t.RoutingInfo.RunningAs.ID == f.unsigneduser.ID {
			target = t
			break
		}
	}
	// if we have no specific target, but a less specific one, use that
	if target == nil && no_user_target != nil {
		target = no_user_target
	}

	if target == nil {
		s := fmt.Sprintf("No target applicable for path %s", servicepath)
		fmt.Println(s)
		return errors.Unavailable(context.Background(), fmt.Sprintf("HTTP registration for \"%s\"", servicepath))
	}
	if *debug_lookup {
		ri := "[no routinginfo"
		if target.RoutingInfo != nil {
			u := target.RoutingInfo.RunningAs
			if u == nil {
				ri = "[routinginfo: nouser]"
			} else {
				ri = fmt.Sprintf("[routinginfo: %s(%s)]", u.ID, u.Email)
			}

		}
		fmt.Printf("Selected target for %s@%s:%d (%s) for User: %s\n", target.ServiceName, target.IP, target.Port, ri, f.userString())
	}

	hf.lastHost = target.IP
	hf.lastPort = int(target.Port)
	return nil
}

// given a host/path combo, insert port into string
func buildHostPortPath(host string, port int) string {
	fv := strings.SplitN(host, "/", 2)
	if len(fv) == 1 {
		s := fmt.Sprintf("%s:%d", host, port)
		return s
	}
	s := fmt.Sprintf("%s:%d/%s", fv[0], port, fv[1])
	return s
}
