package srv

import (
	"context"
	"flag"
	"fmt"
	apb "golang.conradwood.net/apis/auth"
	"golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/apis/weblogin"
	"golang.conradwood.net/go-easyops/auth"
	"golang.conradwood.net/go-easyops/authremote"
	//	"golang.conradwood.net/go-easyops/tokens"
	"golang.yacloud.eu/apis/session"
	"net/http"
	"time"
)

var (
	ssodomain       = flag.String("sso_domain", "yacloud.eu", "set this to your domain, it needs to resolve www. and sso. to redirect to ")
	override_cookie = flag.Bool("cookie_extra_short_lifetime", false, "if set, the cookie will only be valid for 2 seconds, annoying all users (but useful for developing and testing the cookie auth code)")
	wl              weblogin.WebloginClient
	debug_wl        = flag.Bool("debug_weblogin", false, "debug weblogin calls")
)

const (
	WEBLOGIN_SERVICE = "weblogin.Weblogin"
)

func debugWl(txt string, args ...interface{}) {
	if !*debug_wl {
		return
	}
	fmt.Printf("[weblogin_debug] "+txt+"\n", args...)
}

// serve weblogin page.
// returns true if we did not have a user, but have one after calling weblogin
func (f *FProxy) WebLogin() bool {
	debugWl("invoked WebLogin()")
	if wl == nil {
		wl = weblogin.GetWebloginClient()
	}
	debugWl("Serving weblogin...")
	req := f.req
	wreq := &weblogin.WebloginRequest{
		Method:    req.Method,
		Scheme:    f.scheme,
		Host:      req.Host,
		Path:      req.URL.Path,
		Query:     req.URL.RawQuery,
		Submitted: make(map[string]string),
		Body:      string(f.RequestBody()),
		Peer:      f.PeerIP(),
		Cookies:   f.SubmittedCookies(),
		UserAgent: f.GetHeader("user-agent"),
	}

	for k, v := range f.RequestValues() {
		wreq.Submitted[k] = v
	}
	ctx := getUserContext(f)
	if ctx == nil {
		ctx = createBootstrapContext()
	}

	h, err := wl.GetLoginPage(ctx, wreq)
	if f.ProcessError(err, 500, "unable to provide login page") {
		f.AntiDOS("unable to provide login page: %s", err)
		return false
	}
	debugWl("processed without error. (httpcode=%d,Authenticated=%v,Cookies:%#v)", h.HTTPCode, h.Authenticated, h.Cookies)
	if h != nil && h.Session != nil {
		f.session = h.Session
	}
	if h.Token != "" {
		d := f.CookieDomain()
		debugWl("Set cookie (expiry %d seconds, host=%s,domain=%s)\n", h.CookieLivetime, req.Host, d)
		// user authenticated, set cookie and reload
		c := &http.Cookie{Name: "Auth-Token",
			Value:    h.Token,
			Path:     "/",
			Expires:  time.Now().Add(time.Duration(h.CookieLivetime) * time.Second),
			SameSite: http.SameSiteNoneMode,
			Secure:   true,
			Domain:   d,
		}
		if *override_cookie {
			c.Expires = time.Now().Add(time.Duration(2) * time.Second)
		}
		f.setCookie(c)

	}

	if h.User != nil {
		debugWl("weblogin got user %s", h.User.Email)
		su, err := GetSignedUser(ctx, h.User)
		if err != nil {
			fmt.Printf("Getting signed user failed %s", err)
			return false
		}
		f.SetUser(su)
	} else {
		f.SetUser(nil)
	}

	if h.RedirectTo != "" {
		debugWl("weblogin asked to redirect to \"%s\"", h.RedirectTo)
		f.RedirectTo(h.RedirectTo, h.ForceGetAfterRedirect)
		return false // do not retry same url - redirect!
	}

	if !h.Authenticated {
		debugWl("Weblogin requests username and password!\n")
		if h.MimeType != "" {
			f.SetHeader("Content-Type", h.MimeType)
		}
		f.SetStatus(200)
		f.Write(h.Body)
		return false
	}
	debugWl("Weblogin authenticated (user=%s)!", h.User.Email)
	f.SetCookies(h.Cookies)
	return true
}

// called if a user is authenticated but the users' email address is not yet verified
// returns true if email is now verified (we want the users' context so to match the verification code to the user)
func (f *FProxy) WebVerifyEmail(ctx context.Context) bool {
	debugWl("invoked WebVerifyEmail()")
	if wl == nil {
		wl = weblogin.GetWebloginClient()
	}
	debugWl("Serving weblogin (verify email)...")
	req := f.req
	wreq := &weblogin.WebloginRequest{
		Method:    req.Method,
		Scheme:    f.scheme,
		Host:      req.Host,
		Path:      req.URL.Path,
		Query:     req.URL.RawQuery,
		Submitted: make(map[string]string),
		Body:      string(f.RequestBody()),
		Peer:      f.PeerIP(),
		Cookies:   f.SubmittedCookies(),
		UserAgent: f.GetHeader("user-agent"),
	}
	for k, v := range f.RequestValues() {
		wreq.Submitted[k] = v
	}

	h, err := wl.GetVerifyEmail(ctx, wreq)
	if err != nil {
		f.AntiDOS("failed to verify email: %s", err)
		fmt.Printf("Failed to verify email: %s\n", err)
		return false
	}
	if h.Headers != nil {
		for k, v := range h.Headers {
			f.SetHeader(k, v)
		}
	}
	// refresh cache
	if h.Verified && f.unsigneduser != nil {
		f.unsigneduser.EmailVerified = true
		debugWl("[weblogin] - updated cache for user %s\n", auth.Description(f.unsigneduser))
		return true
	}
	f.SetStatus(200)
	f.Write([]byte(h.HTML))
	//	fmt.Printf("Result: %#v\n", h)
	return h.Verified
}
func createWebloginRequest(f *FProxy) *weblogin.WebloginRequest {
	wreq := &weblogin.WebloginRequest{
		Method:    f.req.Method,
		Scheme:    f.scheme,
		Host:      f.req.Host,
		Path:      f.req.URL.Path,
		Query:     f.req.URL.RawQuery,
		Submitted: make(map[string]string),
		Peer:      f.PeerIP(),
		Body:      string(f.RequestBody()),
		Cookies:   f.SubmittedCookies(),
		UserAgent: f.GetHeader("user-agent"),
	}
	for k, v := range f.RequestValues() {
		wreq.Submitted[k] = v
	}
	return wreq
}
func WebLoginProxy(f *FProxy) {
	debugWl("invoked WebLoginProxy()")
	if wl == nil {
		wl = weblogin.GetWebloginClient()
	}
	wreq := createWebloginRequest(f)

	ctx := getUserContext(f)
	if ctx == nil {
		ctx = createBootstrapContext()
	}
	wr, err := wl.ServeHTML(ctx, wreq) // might return error or might return funny status code in body instead
	if err != nil {
		f.AntiDOS("failed to serve html: %s", err)
		if wr != nil && wr.HTTPCode != 0 {
			f.SetStatus(int(wr.HTTPCode))
		} else {
			f.err = err
			f.SetStatus(convertErrorToCode(err))
		}
		if wr != nil && len(wr.Body) != 0 {
			f.Write(wr.Body)
		}
		return
	}
	if wr != nil && wr.Session != nil {
		f.session = wr.Session
	}
	if wr.HTTPCode != 0 {
		f.AntiDOS("failed to serve html: %s", err)
		f.err = fmt.Errorf("Error (weblogin serves http code %d)", wr.HTTPCode)
		f.SetStatus(int(wr.HTTPCode))
		f.Write(wr.Body)
		return
	}

	copyHeaders(wr, f)
	f.SetCookies(wr.Cookies)
	if wr.RedirectTo != "" {
		f.RedirectTo(wr.RedirectTo, wr.ForceGetAfterRedirect)
		return
	}
	if wr.MimeType != "" {
		f.SetHeader("Content-Type", wr.MimeType)
	}
	f.SetStatus(200)
	f.Write(wr.Body)

}
func copyHeaders(w *weblogin.WebloginResponse, f *FProxy) {
	if w.Headers == nil {
		return
	}
	for k, v := range w.Headers {
		f.SetHeader(k, v)
	}
}
func getUserContext(f *FProxy) context.Context {
	var err error
	a := &authResult{}
	a, err = json_auth(f) // always check if we got auth stuff
	if err != nil {
		fmt.Printf("jsonauth failed: %s\n", err)
		return nil
	}
	if a == nil {
		return nil
	}
	if a.User() == nil {
		return nil
	}
	ctx, err := authremote.ContextForUserID(a.User().ID)
	if err != nil {
		fmt.Printf("contextforuser failed: %s\n", err)
		return nil
	}
	return ctx
}

func WebloginCheck(webloginpara string) (*session.Session, *apb.SignedUser, []*h2gproxy.Cookie, error) {
	debugWl("invoked WebloginCheck()")
	if wl == nil {
		wl = weblogin.GetWebloginClient()
	}
	ps := map[string]string{"weblogin": webloginpara}
	wlr := &weblogin.WebloginRequest{Submitted: ps}
	ctx := createBootstrapContext()
	wr, err := wl.VerifyURL(ctx, wlr)
	if err != nil {
		return nil, nil, nil, err
	}

	if wr.User == nil {
		return nil, nil, nil, nil
	}
	su, err := GetSignedUser(ctx, wr.User)
	if err != nil {
		return wr.Session, nil, nil, err
	}
	if len(wr.Cookies) > 0 {
		return wr.Session, su, wr.Cookies, nil
	}
	return wr.Session, su, nil, nil
}
func webloginGetRedirectTarget(f *FProxy) string {
	if wl == nil {
		wl = weblogin.GetWebloginClient()
	}

	wreq := &weblogin.WebloginRequest{
		Method:    f.req.Method,
		Scheme:    f.scheme,
		Host:      f.req.Host,
		Path:      f.req.URL.Path,
		Query:     f.req.URL.RawQuery,
		Submitted: make(map[string]string),
		Peer:      f.PeerIP(),
		Cookies:   f.SubmittedCookies(),
		UserAgent: f.GetHeader("user-agent"),
	}

	ctx := createBootstrapContext()
	wr, err := wl.SaveState(ctx, wreq)
	if err != nil {
		return fmt.Sprintf("https://www.%s/?linkid=errorpage&title=LoginUnavailable", *ssodomain)
	}
	//	pname := "weblogin_state_yacloud"
	pname := wr.URLStateName
	return fmt.Sprintf("https://sso.%s/weblogin/login?%s=%s", *ssodomain, pname, wr.YacloudWebloginState)
}

func GetSignedUser(ctx context.Context, user *apb.User) (*apb.SignedUser, error) {
	if user == nil {
		return nil, nil
	}
	su, err := authremote.GetAuthManagerClient().SignedGetUserByID(ctx, &apb.ByIDRequest{UserID: user.ID})
	if err != nil {
		return nil, err
	}
	return su, nil
}
