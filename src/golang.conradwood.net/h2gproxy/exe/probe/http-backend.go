package probe

import (
	"flag"
	"fmt"
	pb "golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/go-easyops/server"
	"net/http"
	"strings"
	"time"
)

var (
	httpport    = flag.Int("http_prober_port", 9231, "http port to start the html prober server on")
	http_server *http.Server
)

/*****************************************************************************
 start an http server and register it with registry.
 set up a route with h2gproxy to route urls to this http server
 "voila" - probing can commence
 (this code is compiled into the h2gproxy-server)
*****************************************************************************/
func StartHTTPBackend() error {
	if http_server != nil {
		fmt.Printf("Prober backend running already\n")
		return nil
	}
	go func() {
		fmt.Printf("Starting prober backend on port %d...\n", 9231)
		sd := server.NewHTMLServerDef("h2gproxy.Prober")
		sd.SetPort(*httpport)
		server.AddRegistry(sd)
		adr := fmt.Sprintf(":%d", *httpport)
		http_server = &http.Server{
			ReadTimeout:  time.Duration(15) * time.Second,
			WriteTimeout: time.Duration(15) * time.Second,
			Addr:         adr,
		}
		//		server.Handler = httpMux
		http_server.Handler = &foohandler{}
		err := http_server.ListenAndServe()
		if err != nil {
			fmt.Printf("Prober server: %s\n", err)
		}
	}()
	return nil
}
func StopHTTPBackend() {
	if http_server == nil {
		fmt.Printf("Prober backend stopped already\n")
		return
	}
	http_server.Close()
	http_server = nil
}

type foohandler struct {
}

/*****************************************************************************
Requests from the prober arrive here:
*****************************************************************************/
// prober requests to ".../none" end up here
func (f *foohandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	be := &BackendRequest{w: w, req: req}
	be.handle()
}
func (be *BackendRequest) handle() {
	fmt.Printf("[proberbackend] Path: \"%s\", RemoteUser=\"%s\"\n", be.Path(), be.RemoteUser())
	needauth := strings.Contains(be.Path(), "/probers/auth/")
	needauth = needauth || wantAuth(be)
	if needauth && be.RemoteUser() == "" {
		be.WriteHeader(401)
		return
	}
	if strings.HasSuffix(be.Path(), "data") {
		be.sendData()
		return
	}
	if strings.HasSuffix(be.Path(), "post") {
		be.doPost()
		return
	}
	be.WriteHeader(404)
	return
}
func (be *BackendRequest) GetValue(s string) string {
	v := be.req.Form[s]
	if v == nil || len(v) == 0 {
		return ""
	}
	return v[0]
}
func (be *BackendRequest) doPost() {
	err := be.req.ParseForm()
	if err != nil {
		be.sendError(err)
		return
	}
	e := be.GetValue("echo")
	fmt.Printf("Post: echo value: \"%s\"\n", e)
	be.WriteHeader(200)
	be.Write([]byte(PROBE_IDENTIFIER))
	if e != "" {
		be.Write([]byte(e))
	}
	return
}

func (be *BackendRequest) sendData() {
	err := be.req.ParseForm()
	if err != nil {
		be.sendError(err)
		return
	}
	e := be.GetValue("echo")
	be.WriteHeader(200)
	be.Write([]byte(PROBE_IDENTIFIER))
	be.Write([]byte(e))
	return
}

func (be *BackendRequest) sendError(err error) {
	fmt.Printf("Error parsing form: %s\n", err)
	be.w.WriteHeader(500)
	be.w.Write([]byte(fmt.Sprintf("[prober-backend] %s", err)))
	return
}

type BackendRequest struct {
	w   http.ResponseWriter
	req *http.Request
}

func (be *BackendRequest) RemoteUser() string {
	for k, v := range be.req.Header {
		if len(v) == 0 {
			continue
		}
		if strings.ToLower(k) == "remote_user" {
			return v[0]
		}
	}
	return ""
}
func (be *BackendRequest) Path() string {
	return be.req.URL.Path
}

func (be *BackendRequest) WriteHeader(code int) {
	be.w.WriteHeader(code)
}
func (be *BackendRequest) Write(b []byte) {
	be.w.Write(b)
}
func (be *BackendRequest) GetHeaders() []*pb.Header {
	var res []*pb.Header
	for k, v := range be.req.Header {
		res = append(res, &pb.Header{Name: k, Values: v})
	}
	return res
}
func (be *BackendRequest) GetParameters() []*pb.Parameter {
	var res []*pb.Parameter
	return res
}
