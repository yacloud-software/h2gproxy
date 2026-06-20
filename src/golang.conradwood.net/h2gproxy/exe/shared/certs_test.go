package shared

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	xhttp "golang.conradwood.net/go-easyops/http"
	"golang.conradwood.net/go-easyops/utils"
)

func TestChain(t *testing.T) {
	h := &https_req_handler{}
	h.test_start_server(t)
	h.check_tls_server("127.0.0.1", 9323, "l.conradwood.net")

	xhttp.Get("https://localhost:9323")
	<-h.finish
}

func (h *https_req_handler) check_tls_server(addr string, port int, hostname string) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	addr_s := fmt.Sprintf("%s:%d", addr, port)
	conn, err := tls.Dial("tcp", addr_s, conf)
	if err != nil {
		h.t.Logf("failed to connect to \"%s\": %s\n", addr_s, err)
		h.t.FailNow()
		return
	}

	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	for i, cert := range certs {
		h.t.Logf("Certificate #%d", i)
		h.t.Logf("   Issuer Name: %s", cert.Issuer)
		h.t.Logf("   Expiry: %s", cert.NotAfter.Format("2006-January-02"))
		h.t.Logf("   Common Name: %s", cert.Issuer.CommonName)

	}
}
func (h *https_req_handler) test_start_server(t *testing.T) {
	h.finish = make(chan bool)
	h.t = t
	server := &http.Server{
		//		Addr:    "127.0.0.1:9323",
		Handler: h,
	}

	tlsConfig := &tls.Config{}
	// this stuff is important:
	server.TLSConfig = tlsConfig
	// we load all the certs into the server
	tlsConfig.Certificates = AllCerts()
	// and then specify which one to serve for which host
	//	tlsConfig.NameToCertificate = shared.CertMap()
	tlsConfig.GetCertificate = test_getcert

	// open the listener
	l, err := net.Listen("tcp", ":9323")
	if err != nil {
		t.Logf("Failed to listen: %s\n", err)
		t.FailNow()
		return
	}
	// any incoming connections from now on will be queued by the OS
	// and accepted after we call ServeTLS

	go func(srv *http.Server) {
		err := server.ServeTLS(l, "", "")
		//		err := srv.ListenAndServeTLS("", "")
		utils.Bail("failed to start server", err)
	}(server)

}

func test_getcert(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	fmt.Printf("Getcert for \"%s\"\n", chi.ServerName)
	x, err := GetCert(chi.ServerName, time.Duration(5)*time.Second)
	return x, err
}

type https_req_handler struct {
	t      *testing.T
	finish chan bool
}

func (h *https_req_handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	s := "<html><body>Hello World</body></html>"
	w.Write([]byte(s))
	h.finish <- true
}
