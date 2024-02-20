package probe

import (
	"fmt"
	"golang.conradwood.net/go-easyops/utils"
	"net/url"
)

func (p *Probe) NoAuthHTMLGet() *Result {
	res := &Result{
		TestName: "noauth-html-get",
		URL:      fmt.Sprintf("%s/%s", p.BaseURL(), "noauth/html"),
	}
	clid := utils.RandomString(256)
	v := url.Values{"echo": []string{clid}}
	h := res.HTTP()

	hr := h.Get(res.URL + "?" + v.Encode())
	res.SetHTTPResponse(hr)
	if res.Err != nil {
		return res
	}
	if isWebLogin(hr) {
		res.Err = fmt.Errorf("form authentication appeared but not expected")
		return res
	}

	res.CheckBody(hr.Body())
	res.CheckContains(hr.Body(), clid)
	return res
}

func (p *Probe) NoAuthHTMLPost() *Result {
	res := &Result{
		TestName: "noauth-html-post",
		URL:      fmt.Sprintf("%s/%s", p.BaseURL(), "noauth/html"),
	}
	clid := utils.RandomString(256)
	v := url.Values{"echo": []string{clid}}
	h := res.HTTP()

	hr := h.Post(res.URL, []byte(v.Encode()))
	res.SetHTTPResponse(hr)
	if res.Err != nil {
		return res
	}
	if isWebLogin(hr) {
		res.Err = fmt.Errorf("form authentication appeared but not expected")
		return res
	}

	res.CheckBody(hr.Body())
	res.CheckContains(hr.Body(), clid)
	return res
}

func (p *Probe) AuthHTMLGet() *Result {
	res := &Result{
		TestName: "auth-html-get",
		URL:      fmt.Sprintf("%s/%s", p.BaseURL(), "auth/html"),
	}
	clid := utils.RandomString(256)
	v := url.Values{"echo": []string{clid}}
	h := res.HTTP()
	h.SetHeader("user-agent", "proberagent")
	h.SetHeader("Authorization", "Bearer "+p.UserToken)

	hr := h.Get(res.URL + "?" + v.Encode())
	res.SetHTTPResponse(hr)
	if res.Err != nil {
		return res
	}
	if isWebLogin(hr) {
		res.Err = fmt.Errorf("form authentication appeared but not expected")
		return res
	}

	res.CheckBody(hr.Body())
	res.CheckContains(hr.Body(), clid)
	return res
}

func (p *Probe) AuthHTMLPost() *Result {
	res := &Result{
		TestName: "auth-html-post",
		URL:      fmt.Sprintf("%s/%s", p.BaseURL(), "auth/html"),
	}
	clid := utils.RandomString(256)
	v := url.Values{"echo": []string{clid}}
	h := res.HTTP()
	h.SetHeader("Authorization", "Bearer "+p.UserToken)

	hr := h.Post(res.URL, []byte(v.Encode()))
	res.SetHTTPResponse(hr)
	if res.Err != nil {
		return res
	}
	if isWebLogin(hr) {
		res.Err = fmt.Errorf("form authentication appeared but not expected")
		return res
	}

	res.CheckBody(hr.Body())
	res.CheckContains(hr.Body(), clid)
	return res
}

// trigger an authentication via form-based login
func (p *Probe) FormAuthHTMLGet() *Result {
	res := &Result{
		TestName: "form-auth-html-get",
		URL:      fmt.Sprintf("%s/%s", p.BaseURL(), "noauth/html"),
	}
	if p.ProberEmail == "" {
		res.Err = fmt.Errorf("Cannot probe form login without 'ProberEmail' (forgot --prober_email ?)")
		return res
	}
	if p.ProberPassword == "" {
		res.Err = fmt.Errorf("Cannot probe form login without 'ProberPassword' (forgot --prober_password ?)")
		return res
	}
	clid := utils.RandomString(256)
	v := url.Values{"echo": []string{clid}}
	h := res.HTTP()
	h.SetHeader("user-agent", "proberagent")
	h.SetHeader("authme", "true")

	hr := h.Get(res.URL + "?" + v.Encode())
	res.SetHTTPResponse(hr)
	if res.Err != nil {
		return res
	}

	if !isWebLogin(hr) {
		res.Err = fmt.Errorf("form auth not redirected to login (missing weblogin header)")
		return res
	}
	h.SetHeader("authme", "false") // please don't send me around in a loop..

	// we have been redirected to weblogin, now submit form

	nu := hr.FinalURL()
	//	fmt.Printf("Redirected to %s\n", nu)
	v = url.Values{
		"email":    []string{p.ProberEmail},
		"password": []string{p.ProberPassword},
	}

	hr = h.Post(nu, []byte(v.Encode()))
	res.SetHTTPResponse(hr)
	if res.Err != nil {
		return res
	}
	if isWebLogin(hr) {
		res.Err = fmt.Errorf("form authentication appeared after login again (login failure?)")
		return res
	}

	nu = hr.FinalURL()
	//	fmt.Printf("Redirected to %s\n", nu)
	res.CheckBody(hr.Body())
	res.CheckContains(hr.Body(), clid)
	return res
}
