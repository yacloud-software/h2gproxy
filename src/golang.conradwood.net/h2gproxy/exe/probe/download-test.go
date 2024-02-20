package probe

import (
	"fmt"
	"net/url"
	"strings"
)

func (p *Probe) NoAuthStream() *Result {
	res := &Result{
		TestName: "noauth-stream-get",
		URL:      fmt.Sprintf("%s/%s", p.BaseURL(), "noauth/download/data"),
	}
	p.noAuthStreamBob(res, "fooseed", 12*1024*1024)
	p.noAuthStreamBob(res, "justmodifyingthedata", 176*1024*1024)
	return res
}

func (p *Probe) noAuthStreamBob(res *Result, seed string, size int) {
	if res.Err != nil {
		return
	}

	h := res.HTTP()

	v := url.Values{"seed": []string{seed}, "size": []string{fmt.Sprintf("%d", size)}}
	vs := v.Encode()
	// get the checksum first
	res.URL = fmt.Sprintf("%s/%s", p.BaseURL(), "noauth/download/checksum?"+vs)
	hr := h.Get(res.URL)
	res.SetHTTPResponse(hr)
	if res.Err != nil {
		return
	}
	if isWebLogin(hr) {
		res.Err = fmt.Errorf("form authentication appeared but not expected")
		return
	}
	res.CheckBody(hr.Body())
	l := strings.Split(string(hr.Body()), "\n")
	if len(l) == 0 {
		res.Err = fmt.Errorf("Body did not contained 0 lines (%s)", string(hr.Body()))
	}
	chksum := strings.TrimPrefix(l[0], "DATA CHECKSUM ")
	//	fmt.Printf("Checksum: \"%s\"\n", chksum)

	// get the data now
	res.URL = fmt.Sprintf("%s/%s", p.BaseURL(), "noauth/download/data?"+vs)
	hr = h.Get(res.URL)
	res.SetHTTPResponse(hr)
	if res.Err != nil {
		return
	}
	if isWebLogin(hr) {
		res.Err = fmt.Errorf("form authentication appeared but not expected")
		return
	}
	chck := CheckSum(hr.Body()) // overlap usage of the backend. also used here
	if chck != chksum {
		fmt.Printf("Checksum reported: \"%s\"\n", chksum)
		fmt.Printf("Checksum received: \"%s\"\n", chck)
		res.Err = fmt.Errorf("Mismatching checksum for seed=\"%s\", size=\"%d\"", seed, size)
		return
	}
	res.CheckBody(hr.Body())
	return
}
