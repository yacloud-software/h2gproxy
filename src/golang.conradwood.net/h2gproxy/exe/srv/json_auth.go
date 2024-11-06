package srv

// the various ways a json api can authenticate...
// basic auth
// auth-bearer header
// cookie (if used by webbrowser)

import (
	"golang.conradwood.net/apis/antidos"
	apb "golang.conradwood.net/apis/auth"
	"golang.conradwood.net/go-easyops/common"

	//	"golang.conradwood.net/go-easyops/tokens"
	"net/url"
	"strings"

	"golang.conradwood.net/go-easyops/utils"
)

type authResult struct {
	f            *FProxy
	signedUser   *apb.SignedUser
	unsignedUser *apb.User
	attempted    bool
}

func (a *authResult) SignedUser() *apb.SignedUser {
	return a.signedUser
}
func (a *authResult) User() *apb.User {
	if a.signedUser == nil {
		return nil
	}
	if a.unsignedUser == nil {
		a.unsignedUser = common.VerifySignedUser(a.signedUser)
	}
	if a.unsignedUser == nil {
		panic("signed user does not match signature")
	}

	return a.unsignedUser
}

func (a *authResult) GotCredentials() bool {
	return a.attempted
}
func (a *authResult) Authenticated() bool {
	if a.User() != nil {
		return true
	}
	return false
}

// always returns an authresult. to determine if it IS authenticated call authResult.Authenticated()
func json_auth(f *FProxy) (*authResult, error) {
	res := &authResult{f: f}
	if f.signeduser != nil {
		res.signedUser = f.signeduser
		return res, nil
	}

	res.UserFromBearer()
	res.UserFromCookie()
	res.UserFromWeblogin()
	res.UserFromParameter()
	res.UserFromBasicAuth()
	if f.NeedsAuth() && res.attempted && !res.Authenticated() {
		antidos.GetAntiDOSClient().IPFailure(createBootstrapContext(), &antidos.IPFailureRequest{
			IP:      f.PeerIP(),
			Message: "could not authenticate access to " + f.String() + " by any means",
		})
	}
	return res, nil
}

// sets the authresult to user from 'apikey=' url parameter
// true if auth was necessary, attempted and succesful
func (a *authResult) UserFromParameter() bool {
	if a.f.unsigneduser != nil {
		return false
	}
	if a.f.req == nil {
		return false
	}
	params, err := url.ParseQuery(a.f.req.URL.RawQuery)
	if err != nil {
		a.f.Printf("Failed to parse form: %s\n", err)
		return false
	}
	for k, v := range params {
		if k != "apikey" {
			continue
		}
		a.attempted = true
		for _, tok := range v {
			user, err := TokenToUser(tok)
			if err != nil {
				a.f.Printf("Failed to resolve apikey: %s\n", utils.ErrorString(err))
				return false
			}
			if user == nil {
				a.f.Printf("no user for apikey\n")
				return false
			}
			a.signedUser = user
			a.f.SetUser(user)
			return true
		}
	}
	return false

}

// sets the authresult to user or hesthing
// true if auth was succesful
func (a *authResult) UserFromBearer() bool {
	if a.f.unsigneduser != nil {
		return false
	}
	if a.f.req == nil {
		return false
	}
	if a.f.req.Header == nil {
		return false
	}
	s := a.f.req.Header.Get("Authorization")
	if s == "" {
		return false
	}
	if !strings.HasPrefix(s, "Bearer ") {
		return false
	}
	s = strings.TrimPrefix(s, "Bearer ")

	a.attempted = true

	// check bearer for user account
	// we ignore errors until this is the ONLY source
	// for now, we must ignore error and continue to
	// check if it's a hes token

	// check if token is a user token (calls AuthenticationService.GetUserByToken())
	// AuthenticationService.GetUserByToken() calls authbe.Authenticate(token)
	// authbe.Authenticate(token) checks against a token in the usertoken table
	u, err := TokenToUser(s)
	if err == nil && u != nil {
		a.signedUser = u
		return true
	}
	if *debug && err != nil {
		a.f.Printf("error resolving token to user: %s\n", err)
	}

	return true
}

// this tries to figure out which user is making this request
// and if it can, will set f.user
func (a *authResult) UserFromCookie() *apb.SignedUser {
	if a.f.signeduser != nil {
		return a.f.signeduser
	}

	c, err := a.f.req.Cookie(COOKIE_NAME)
	if err != nil {
		return nil
	}
	a.attempted = true
	u := GetUserFromCookie(c)
	if u == nil {
		return nil
	}

	a.signedUser = u
	return u
}

// if sso.yacloud.eu redirected us back to [url]?weblogin=foobar then
// pass foobar to weblogin. If weblogin is happy, add the user and a cookie
func (a *authResult) UserFromWeblogin() *apb.SignedUser {
	if a.f.signeduser != nil {
		return a.f.signeduser
	}
	wls := a.f.QueryValues()["weblogin"]
	if wls == "" {
		return nil
	}
	sess, u, c, err := WebloginCheck(wls)
	if err != nil {
		a.f.Printf("Weblogin failed: %s\n", err)
		return nil
	}
	if sess != nil {
		a.f.session = sess
	}
	if u == nil {
		// weblogin does not think this is valid
		return nil
	}
	a.f.SetCookies(c)
	a.attempted = true
	return u
}

func (a *authResult) UserFromBasicAuth() {
	if a.f.unsigneduser != nil {
		return
	}
	u, p, gotit := a.f.req.BasicAuth()
	if *debug {
		a.f.Printf("[jsonauth] Basicauth u=\"%s\" p(len)=\"%d\" (%v)\n", u, len(p), gotit)
	}
	if !gotit {
		return
	}
	a.attempted = true
	if u == "" || p == "" {
		// doesn't count, stuff is empty
		return
	}
	us, err := a.f.authenticateUser(u, p)
	if err != nil {
		a.f.Printf("[jsonauth] failed to authenticate user %s: %s\n", u, err)
		return
	}
	if us == nil {
		a.f.Printf("[jsonauth] no user, but basic auth\n")
		return
	}
	a.signedUser = us
}
