package srv

// this is the https endpoint. Once it terminated the TLS connection it
// will call the (non-tls) http handler.

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"

	pb "golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/h2gproxy/shared"

	//	"golang.conradwood.net/go-easyops/tokens"
	"net/http"
	"time"
)

var (
	//	https_is_ready = false
	disable_http2 = flag.Bool("disable_http2", true, "http2 implementation seems to randomly throw GOAWAY errors with go get")
	httpsport     = flag.String("https_port", "4443", "The port to start the HTTPs listener on")
	//	certdir     = flag.String("certs_dir", "/etc/certs", "The directory in which the certs live (one dir per hostname, certificate.pem and key.pem in each direcetory")
	tlsConfig *tls.Config
)

func (r *HTTPForwarder) StopTLS() error {
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

func StartHTTPSServer() error {
	if *httpsport == "" {
		return errors.New("refusing to start https server on port 0")
	}
	ld := &pb.AddConfigHTTPRequest{
		TargetService: WEBLOGIN,
		ConfigName:    "weblogin",
	}
	loginTarget = &HTTPForwarder{def: ld}

	cf := true
	for _, port := range portsFromString(*httpsport) {
		adr := fmt.Sprintf(":%d", port)
		fmt.Printf("Starting https server on port %s\n", adr)
		er := startHTTPS(loginTarget, adr, port)
		if er == nil {
			fmt.Printf("HTTPS server started.\n")
			if cf {
				cf = false
			}
		} else {
			return er
		}

	}
	return nil
}

// silly function to check startup of https
func startHTTPS(r *HTTPForwarder, adr string, port int) error {
	go func() {
		//		httpsMux := http.NewServeMux()
		f := &https_req_handler{port: port}
		//		httpsMux.HandleFunc("/", f.https_handler)
		r.server = &http.Server{
			Addr:    adr,
			Handler: f,
		}
		if *disable_http2 {
			r.server.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
		}
		tlsConfig = &tls.Config{}
		// this stuff is important:
		r.server.TLSConfig = tlsConfig
		// we load all the certs into the server
		tlsConfig.Certificates = shared.AllCerts()
		// and then specify which one to serve for which host
		tlsConfig.NameToCertificate = shared.CertMap()
		tlsConfig.GetCertificate = getcert
		// and then start the server
		r.server.ListenAndServeTLS("", "")
	}()
	return nil
}
func getcert(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return shared.GetCert(chi.ServerName, time.Duration(3)*time.Second)
}

type https_req_handler struct {
	port int
}

func (h *https_req_handler) https_handler(w http.ResponseWriter, r *http.Request) {
	main_handler(w, r, true, h.port)
}
func (h *https_req_handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Host == "" {
		http.Error(w, "no host", 400)
		fmt.Printf("No host specified\n")
		return
	}
	main_handler(w, r, true, h.port)

}
