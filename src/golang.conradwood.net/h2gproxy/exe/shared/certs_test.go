package shared

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"testing"
	"time"

	"golang.conradwood.net/go-easyops/utils"
)

func TestChain(t *testing.T) {
	test_start_server(t)
}
func test_start_server(t *testing.T) {
	f := &https_req_handler{t: t}
	server := &http.Server{
		Addr:    "127.0.0.1:9323",
		Handler: f,
	}

	tlsConfig := &tls.Config{}
	// this stuff is important:
	server.TLSConfig = tlsConfig
	// we load all the certs into the server
	tlsConfig.Certificates = AllCerts()
	// and then specify which one to serve for which host
	//	tlsConfig.NameToCertificate = shared.CertMap()
	tlsConfig.GetCertificate = test_getcert
	// and then start the server
	err := server.ListenAndServeTLS("", "")
	utils.Bail("failed to start server", err)

}

func test_getcert(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	fmt.Printf("Getcert for \"%s\"\n", chi.ServerName)
	x, err := GetCert(chi.ServerName, time.Duration(5)*time.Second)
	return x, err
}

type https_req_handler struct {
	t *testing.T
}

func (h *https_req_handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	s := "<html><body>Hello World</body></html>"
	w.Write([]byte(s))
}
