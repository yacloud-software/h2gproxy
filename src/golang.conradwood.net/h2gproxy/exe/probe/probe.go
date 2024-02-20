package probe

import (
	"fmt"
	"golang.conradwood.net/go-easyops/http"
	"golang.conradwood.net/go-easyops/utils"
	"os"
	"strings"
)

const (
	BASE_PATH        = "probers"
	PROBE_IDENTIFIER = `kai3no7ahzohoo1thoogaetaexooj8EecheiMoolai8gieth3aN4ikaimeil5ashahtheedie5bah8OzoiXie7shie2ohBohWushie3sewoezeipheeko0Toth9eu9oheib5Zautah3taa0wu6fo8oor4koongaag5ieVoye1ookei8Kiwie6Gah5ohSh3einiezewahbae0Phethohso5Ooy6eR7peiziexi4nei9of0oiy4ei1eo8mohxiM6po`
)

var (
	started = false
)

func Start() error {
	started = true
	return nil
}

type Probe struct {
	UserToken string
	Host      string
	/* credentials to use form-based login with */
	ProberEmail    string
	ProberPassword string
}

func (p *Probe) BaseURL() string {
	s := fmt.Sprintf("https://%s/%s", strings.Trim(p.Host, "/"), strings.Trim(BASE_PATH, "/"))
	return s
}

// run probes, print result, then exit
func (p *Probe) AllTestsAndExit() {
	p.CheckReady()
	failed := false
	results := p.AllTests()
	fmt.Printf("------------- Probe Results ---------\n")
	for _, r := range results {
		failed = failed || r.Failed()
		s := r.String()
		if len(s) > 170 {
			s = s[:170] + "..."
		}
		fmt.Println(s)
	}
	if failed {
		fmt.Printf("Probes failed.\n")
		os.Exit(10)
	}
	fmt.Printf("Probes passed.\n")
	os.Exit(0)

}

func (p *Probe) AllTests() []*Result {
	p.CheckReady()
	var res []*Result
	/*
		// json is now same as _HTML_
				res = append(res, p.NoAuthJSONGet())
					res = append(res, p.NoAuthJSONPost())
					res = append(res, p.AuthJSONGet())
					res = append(res, p.AuthJSONPost())
					res = append(res, p.FormAuthJSONGet())
	*/
	res = append(res, p.FormAuthNoneGet())
	res = append(res, p.AuthNoneGet())
	res = append(res, p.NoAuthNonePost())
	res = append(res, p.NoAuthNoneGet())
	res = append(res, p.NoAuthStream())
	res = append(res, p.NoAuthHTMLGet())
	res = append(res, p.NoAuthHTMLPost())
	res = append(res, p.AuthHTMLGet())
	res = append(res, p.AuthHTMLPost())
	res = append(res, p.FormAuthHTMLGet())

	return res
}

type Result struct {
	TestName string
	URL      string // url used to execute probe
	Err      error  // nil if ok
	hr       *http.HTTPResponse
	ht       *http.HTTP
}

func (r *Result) SetHTTPResponse(h *http.HTTPResponse) {
	if !started {
		panic("must call probe.Start() first")
	}
	e := h.Error()
	// do not clear errors. once we got one, keep it (or overwrite with a newer one)
	if e == nil && r.Err != nil {
		return
	}
	r.hr = h
	r.Err = e
}
func (r *Result) HTTP() *http.HTTP {
	if !started {
		panic("must call probe.Start() first")
	}
	if r.ht == nil {
		r.ht = &http.HTTP{}
	}
	return r.ht
}

// if body does not contain identifier, set error
func (r *Result) CheckContains(body []byte, txt string) {
	s := string(body)
	if !strings.Contains(s, txt) {
		short := s
		if len(short) > 100 {
			short = short[:100] + "..."
		}
		short = strings.ReplaceAll(short, "\n", " ")
		r.Err = fmt.Errorf("%d bytes, missing text in \"%s\"", len(body), short)
	}
}

// if body does not contain identifier, set error
func (r *Result) CheckBody(body []byte) {
	r.CheckContains(body, PROBE_IDENTIFIER)
}
func (r *Result) Failed() bool {
	return r.Err != nil
}
func (r *Result) String() string {
	if !started {
		panic("must call probe.Start() first")
	}
	st := "OK"
	if r.hr != nil {
		st = fmt.Sprintf("OK (%s)", utils.PrettyNumber(uint64(len(r.hr.Body()))))
	}
	code := ""
	if r.hr != nil {
		code = fmt.Sprintf(" %03d", r.hr.HTTPCode())
	}
	if r.Err != nil {
		st = fmt.Sprintf("FAILED %s (%s)", r.URL, r.Err)
	}
	return fmt.Sprintf("[%20s]%s %s", r.TestName, code, st)
}

// panics if not ready
func (p *Probe) CheckReady() {
	if !started {
		panic("must call probe.Start() first")
	}
	if p.Host == "" {
		panic("hostname must be set")
	}
	if p.ProberEmail == "" {
		panic("email must be set")
	}
	if p.ProberPassword == "" {
		panic("password must be set")
	}
	if p.UserToken == "" {
		panic("token must be set")
	}

}
