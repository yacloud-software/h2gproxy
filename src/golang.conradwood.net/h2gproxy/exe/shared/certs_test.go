package shared

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.conradwood.net/go-easyops/errors"
	xhttp "golang.conradwood.net/go-easyops/http"
	"golang.conradwood.net/go-easyops/utils"
)

const (
	//	TEST_HOST = "l.conradwood.net"
	TEST_HOST = "www.carbonsaver.co.uk"
)

func TestChain(t *testing.T) {
	stop()
	h := &https_req_handler{}
	h.test_start_server(t)
	h.check_tls_server("127.0.0.1", 9323, TEST_HOST)
	stop()
	t.Logf("waiting for finish signal")
	<-h.finish

}

func stop() {
	xhttp.Get("https://" + TEST_HOST + ":9323")
}
func (h *https_req_handler) check_tls_server(addr string, port int, hostname string) {
	h.t.Logf("priming certificate")
	_, err := GetCert(TEST_HOST, time.Duration(5)*time.Second)
	if err != nil {
		h.t.Logf("failed to get cert: %s\n", errors.ErrorString(err))
		h.t.Fail()
		return
	}
	h.t.Logf("got certificate")

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
	var allcerts []*x509.Certificate
	allcerts = append(allcerts, conn.ConnectionState().PeerCertificates...)
	for _, chain := range conn.ConnectionState().VerifiedChains {
		allcerts = append(allcerts, chain...)
	}

	certs := conn.ConnectionState().PeerCertificates
	i := 0
	for _, cert := range certs {
		i++
		h.printCert(i, cert, allcerts)
	}
	for _, chain := range conn.ConnectionState().VerifiedChains {
		for _, cert := range chain {
			i++
			h.printCert(i, cert, allcerts)
		}
	}
}
func (h *https_req_handler) printCert(i int, cert *x509.Certificate, allcerts []*x509.Certificate) {
	subject := fmt.Sprintf("%s", cert.Subject.CommonName)
	opts := x509.VerifyOptions{DNSName: subject, Intermediates: x509.NewCertPool()}
	for _, c := range allcerts {
		opts.Intermediates.AddCert(c)
	}
	b, err := cert.Verify(opts)
	vs := ""
	if err != nil {
		cve, ok := err.(*tls.CertificateVerificationError)
		if ok {
			for _, ucert := range cve.UnverifiedCertificates {
				h.t.Logf("Unverified: %s\n", ucert.Subject)
			}
		} else {
			vs = fmt.Sprintf("ERR: %s", err)
		}
	} else {
		vs = fmt.Sprintf("%v", b)
	}
	h.t.Logf("Certificate #%d (CA: %v, Verified against \"%s\": %s)\n", i, cert.IsCA, subject, vs)
	h.t.Logf("   CommonName : %s", cert.Subject.CommonName)
	h.t.Logf("   Subject    : %s", cert.Subject)
	h.t.Logf("   Issuer Name: %s", cert.Issuer)
	h.t.Logf("   Expiry: %s", cert.NotAfter.Format("2006-January-02"))
	h.t.Logf("   Common Name: %s", cert.Issuer.CommonName)

}

func (h *https_req_handler) test_start_server(t *testing.T) {
	// open the listener
	l, err := net.Listen("tcp", ":9323")
	if err != nil {
		stop()
		time.Sleep(time.Duration(1) * time.Second)
		l, err = net.Listen("tcp", ":9323")
		if err != nil {
			t.Logf("Failed to listen: %s\n", err)
			t.FailNow()
			return
		}
	}
	h.finish = make(chan bool, 10)
	h.t = t

	server := &http.Server{
		//		Addr:    "127.0.0.1:9323",
		Handler: h,
		TLSConfig: &tls.Config{
			// we load all the certs into the server
			Certificates: AllCerts(),
			// and then specify which one to serve for which host
			//	tlsConfig.NameToCertificate = shared.CertMap()
			GetCertificate: test_getcert,
		},
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
	fmt.Printf(" [certhandler] Getcert for \"%s\"\n", chi.ServerName)
	x, err := GetCert(chi.ServerName, time.Duration(5)*time.Second)
	if err != nil {
		fmt.Printf("  [certhandler] failed to get cert for \"%s\": %s\n", chi.ServerName, errors.ErrorString(err))
	} else {
		fmt.Printf(" [certhanlder] Gotcert for \"%s\"\n", chi.ServerName)
	}
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

// zeroSource is an io.Reader that returns an unlimited number of zero bytes.
type zeroSource struct{}

func (zeroSource) Read(b []byte) (n int, err error) {
	clear(b)
	return len(b), nil
}
