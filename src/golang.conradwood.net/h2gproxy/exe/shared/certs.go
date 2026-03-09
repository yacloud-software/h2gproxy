package shared

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.conradwood.net/apis/certmanager"
	"golang.conradwood.net/apis/common"
	"golang.conradwood.net/go-easyops/authremote"
	"golang.conradwood.net/go-easyops/cache"
	"golang.conradwood.net/go-easyops/errors"
	"golang.conradwood.net/go-easyops/utils"
)

var (
	certs_are_ready    = false
	last_cert_refresh  time.Time
	failed_certs_cache = cache.New("h2gproxy_failed_certs_cache", time.Duration(30)*time.Minute, 500)
	certmap            = make(map[string]*tls.Certificate)
	certs              []tls.Certificate
	certLock           sync.Mutex
	single_cert        = flag.String("cert_host", "", "if set, only retrieve and service this certificate")
	debug              = utils.DebugFlag("certmanager")
	certs_starting_up  sync.Mutex // locked until certs retrieved
)

func init() {
	certs_starting_up.Lock()
	go cert_refresher()
}

// run a loop to periodically retrieve certificates from certmanager
func cert_refresher() {
	t := time.Duration(3) * time.Second
	if *single_cert != "" {
		t = time.Duration(100) * time.Millisecond
	}
	for {
		time.Sleep(t)
		err := cert_refresh()
		if err != nil {
			fmt.Printf("Failed to refresh certs: %s\n", utils.ErrorString(err))
		} else {
			t = time.Duration(600) * time.Second
			if !certs_are_ready {
				certs_are_ready = true
				certs_starting_up.Unlock()
			}

		}
	}
}

// load all certificates...

func cert_refresh() error {
	if time.Since(last_cert_refresh) < time.Duration(15)*time.Second {
		return nil
	}
	last_cert_refresh = time.Now()
	certLock.Lock()
	defer certLock.Unlock()
	fmt.Printf("[certs] refreshing...\n")
	ctx := authremote.Context()
	var certlist *certmanager.CertNameList
	//var certlist string
	var err error
	if *single_cert == "" {
		certlist, err = certmanager.GetCertManagerClient().ListPublicCertificates(ctx, &common.Void{})
		if err != nil {
			return err
		}
	} else {
		certlist = &certmanager.CertNameList{Certificates: []*certmanager.CertInfo{
			&certmanager.CertInfo{Hostname: *single_cert},
		}}
	}
	newcerts := make(map[string]*tls.Certificate)
	for _, c := range certlist.Certificates {
		debug.Debugf("cert: %s\n", c.Hostname)
		//		ctx := createBootstrapContext()
		ctx := authremote.Context()
		pcr := &certmanager.PublicCertRequest{Hostname: c.Hostname}
		cert, err := certmanager.GetCertManagerClient().GetPublicCertificate(ctx, pcr)
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
			xcert, xerr := x509.ParseCertificate(block.Bytes)
			if xerr != nil {
				fmt.Printf("[certs] Cannot parse certificate %s: %s\n", cert.Cert.Host, err)
				return err
			}
			now := time.Now()
			if now.After(xcert.NotAfter) {
				fmt.Printf("[certs] certificate for \"%s\" expired on %v\n", c.Hostname, xcert.NotAfter)
				continue
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
	certmap = newcerts
	fmt.Printf("[certs] %d Certs loaded\n", len(certs))
	return nil
}

// do we have a certificate for this host?
func HaveCert(name string) bool {
	WaitForCerts()
	for k, _ := range certmap {
		if k == name {
			return true
		}
	}
	// we've been asked if a we have a certificate and we do not. Tell certmanager to get one for us...
	return false
}

func GetCert(hostname string, timeout time.Duration) (*tls.Certificate, error) {
	WaitForCerts()
	c := certmap[hostname]
	if c != nil {
		return c, nil
	}
	go request(hostname)
	time.Sleep(timeout)
	c = certmap["public.conradwood.net"] // our default
	if c != nil {
		return c, nil
	}
	//	fmt.Printf("servername: \"%s\"\n", hostname)
	return nil, errors.Errorf("no such certificate: %s", hostname)

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
	ctx := authremote.Context()
	pcr := &certmanager.PublicCertRequest{Hostname: name}
	// does certmanager have the cert (and we don't?)
	_, err := certmanager.GetCertManagerClient().GetPublicCertificate(ctx, pcr)
	if err == nil {
		err = cert_refresh()
		if err != nil {
			fmt.Printf("failed to refresh certificates: %s\n", err)
		}
		return

	}

	_, err = certmanager.GetCertManagerClient().RequestPublicCertificate(ctx, pcr)
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
		ctx := authremote.Context()
		_, err := certmanager.GetCertManagerClient().GetPublicCertificate(ctx, pcr)
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
func AllCerts() []tls.Certificate {
	WaitForCerts()
	return certs
}
func CertMap() map[string]*tls.Certificate {
	WaitForCerts()
	return certmap
}

func WaitForCerts() {
	if certs_are_ready {
		return
	}
	certs_starting_up.Lock()
	certs_starting_up.Unlock()
}
