package main

// this is the https endpoint. Once it terminated the TLS connection it
// will call the (non-tls) http handler.

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	cm "golang.conradwood.net/apis/certmanager"
	"golang.conradwood.net/apis/common"
	pb "golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/go-easyops/cache"
	"golang.conradwood.net/go-easyops/tokens"
	"golang.conradwood.net/go-easyops/utils"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	httpsport = flag.String("https_port", "", "The port to start the HTTPs listener on")
	//	certdir     = flag.String("certs_dir", "/etc/certs", "The directory in which the certs live (one dir per hostname, certificate.pem and key.pem in each direcetory")
	certmap            = make(map[string]*tls.Certificate)
	certs              []tls.Certificate
	tlsConfig          *tls.Config
	certLock           sync.Mutex
	certManager        cm.CertManagerClient
	got_certs_once     = false
	failed_certs_cache = cache.New("h2gproxy_failed_certs_cache", time.Duration(30)*time.Minute, 500)
)

// run a loop to periodically retrieve certificates from certmanager
func cert_refresher() {
	if certManager == nil {
		certManager = cm.GetCertManagerClient()
	}
	for {
		if got_certs_once {
			time.Sleep(time.Duration(8) * time.Hour)
		} else {
			time.Sleep(time.Duration(3) * time.Second)
		}
		err := cert_refresh()
		if err != nil {
			fmt.Printf("Failed to refresh certs: %s\n", utils.ErrorString(err))
		} else {
			got_certs_once = true
		}
	}
}

// load all certificates...

func cert_refresh() error {
	certLock.Lock()
	defer certLock.Unlock()
	fmt.Printf("[certs] refreshing...\n")
	ctx := tokens.ContextWithToken()
	certlist, err := certManager.ListPublicCertificates(ctx, &common.Void{})
	if err != nil {
		return err
	}
	newcerts := make(map[string]*tls.Certificate)
	for _, c := range certlist.Certificates {
		if *debug {
			fmt.Printf("[certs] cert: %s\n", c.Hostname)
		}
		ctx := tokens.ContextWithToken()
		pcr := &cm.PublicCertRequest{Hostname: c.Hostname}
		cert, err := certManager.GetPublicCertificate(ctx, pcr)
		if err != nil {
			fmt.Printf("[certs] Failed to load cert %s: %s\n", pcr.Hostname, err)
			continue
		}
		// TODO - change this to use cert.TLS* instead
		tc, err := tls.X509KeyPair([]byte(cert.Cert.PemCertificate), []byte(cert.Cert.PemPrivateKey))
		if err != nil {
			fmt.Printf("[certs] Failed to parse cert %s: %s\n", pcr.Hostname, err)
			continue
		}
		// add the ca:
		block, _ := pem.Decode([]byte(cert.Cert.PemCA))
		if block == nil {
			fmt.Printf("[certs] certificate %s has no CA certificate\n", cert.Cert.Host)
		} else {
			_, xerr := x509.ParseCertificate(block.Bytes)
			if xerr != nil {
				fmt.Printf("[certs] Cannot parse certificate %s: %s\n", cert.Cert.Host, err)
				return err
			}

			b := &bytes.Buffer{}
			err = pem.Encode(b, block)
			if err != nil {
				return err
			}
			tc.Certificate = append(tc.Certificate, block.Bytes)
		}
		newcerts[c.Hostname] = &tc

	}
	var newcertlist []tls.Certificate
	for _, v := range newcerts {
		newcertlist = append(newcertlist, *v)
	}
	certs = newcertlist
	if tlsConfig != nil {
		tlsConfig.Certificates = certs
		tlsConfig.NameToCertificate = certmap
	}
	certmap = newcerts
	fmt.Printf("[certs] %d Certs loaded\n", len(certs))
	return nil
}

// do we have a certificate for this host?
func HaveCert(name string) bool {
	for k, _ := range certmap {
		if k == name {
			return true
		}
	}
	// we've been asked if a we have a certificate and we do not. Tell certmanager to get one for us...
	return false
}
func request(name string) {
	if failed_certs_cache.Get(name) != nil {
		// do not attempt to keep getting a failed cert
		return
	}
	if name == "" {
		return
	}
	if strings.HasSuffix(name, ".localdomain") {
		return
	}
	if strings.HasSuffix(name, ".local") {
		return
	}
	if strings.Contains(name, "localhost") {
		return
	}
	idx := strings.Index(name, ":")
	if idx != -1 {
		name = name[:idx]
	}
	fmt.Printf("Requesting \"%s\"\n", name)
	ctx := tokens.ContextWithToken()
	pcr := &cm.PublicCertRequest{Hostname: name}
	// does certmanager have the cert (and we don't?)
	_, err := certManager.GetPublicCertificate(ctx, pcr)
	if err == nil {
		err = cert_refresh()
		if err != nil {
			fmt.Printf("failed to refresh certificates: %s\n", err)
		}
		return

	}

	_, err = certManager.RequestPublicCertificate(ctx, pcr)
	if err != nil {
		failed_certs_cache.Put(name, "foo")
		fmt.Printf("[certs] failed to request cert \"%s\" on the fly: %s\n", pcr.Hostname, err)
		return
	}
	started := time.Now()
	t := time.Duration(1) * time.Second
	i := 0
	for {
		if time.Since(started) > time.Duration(3)*time.Minute {
			fmt.Printf("[certs] timeout for cert \"%s\"\n", pcr.Hostname)
			break
		}
		time.Sleep(t)
		ctx := tokens.ContextWithToken()
		_, err := certManager.GetPublicCertificate(ctx, pcr)
		if err == nil {
			break
		}
		i = i + 3
		if i > 30 {
			i = 30
		}
		t = time.Duration(i) * time.Second
	}
	err = cert_refresh()
	if err != nil {
		fmt.Printf("failed to refresh certificates: %s\n", err)
	}
}

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
	if certManager == nil {
		certManager = cm.GetCertManagerClient()
	}

	cf := true
	for _, port := range portsFromString(*httpsport) {
		adr := fmt.Sprintf(":%d", port)
		fmt.Printf("Starting https server on port %s\n", adr)
		er := startHTTPS(loginTarget, adr, port)
		if er == nil {
			fmt.Printf("HTTPS server started.\n")
			if cf {
				cf = false
				go cert_refresher()
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
		httpsMux := http.NewServeMux()
		f := &https_req_handler{port: port}
		httpsMux.HandleFunc("/", f.https_handler)
		r.server = &http.Server{
			Addr:    adr,
			Handler: httpsMux,
		}
		tlsConfig = &tls.Config{}
		// this stuff is important:
		r.server.TLSConfig = tlsConfig
		// we load all the certs into the server
		tlsConfig.Certificates = certs
		// and then specify which one to serve for which host
		tlsConfig.NameToCertificate = certmap
		tlsConfig.GetCertificate = getcert
		// and then start the server
		r.server.ListenAndServeTLS("", "")
	}()
	return nil
}
func getcert(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	hostname := chi.ServerName
	c := certmap[hostname]
	if c != nil {
		return c, nil
	}
	go request(hostname)
	c = certmap["public.conradwood.net"] // our default
	if c != nil {
		return c, nil
	}
	//	fmt.Printf("servername: \"%s\"\n", hostname)
	return nil, fmt.Errorf("no such certificate: %s", hostname)
}

type https_req_handler struct {
	port int
}

func (h *https_req_handler) https_handler(w http.ResponseWriter, r *http.Request) {
	main_handler(w, r, true, h.port)
}
