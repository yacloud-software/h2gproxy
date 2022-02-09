package main

import (
	"context"
	"fmt"
	au "golang.conradwood.net/apis/auth"
	"golang.conradwood.net/apis/common"
	"golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/go-easyops/authremote"
	"golang.conradwood.net/go-easyops/utils"
	"net/http"
	"time"
)

const (
	SESSION_COOKIE_NAME = "Yei0neez1ohyohnith6iger6Oogexoox"
)

func (f *FProxy) isSessionValid(ctx context.Context, session string) bool {
	if session == "" {
		return false
	}
	am := authremote.GetAuthManagerClient()
	if am == nil {
		fmt.Printf("could not get authmanager\n")
		return false
	}
	if ctx == nil {
		return false
	}
	sign_sess, err := am.KeepAliveSession(ctx, &au.SessionToken{Token: session})
	f.session = sign_sess
	if err != nil {
		fmt.Printf("session not valid: %s\n", err)
		return false
	}
	return true
}

// get or create a session token
// called (or should be called) before calling a backend
func (f *FProxy) GetSessionToken() (string, error) {
	ctx := f.ctx
	if ctx == nil {
		ctx = authremote.Context()
	}
	if f.session_cookie != "" {
		return f.session_cookie, nil
	}
	am := authremote.GetAuthManagerClient()
	if am == nil {
		fmt.Printf("could not get authmanager\n")
		return "", fmt.Errorf("no authmanager")
	}
	c, err := f.req.Cookie(SESSION_COOKIE_NAME)
	if err != nil && err != http.ErrNoCookie {
		return "", err
	}
	if c != nil && f.isSessionValid(ctx, c.Value) {
		return c.Value, nil
	}
	if ctx == nil {
		fmt.Printf("No context to create session\n")
		return "", fmt.Errorf("No context to create session")
	}
	sign_sess, err := am.CreateSession(ctx, &common.Void{})
	if err != nil {
		fmt.Printf("Could not get session: %s\n", utils.ErrorString(err))
		return "", err
	}
	f.session = sign_sess
	sess := &au.Session{}
	err = utils.UnmarshalBytes(sign_sess.Session, sess)
	if err != nil {
		return "", err
	}
	hc := &h2gproxy.Cookie{
		Name:   SESSION_COOKIE_NAME,
		Value:  sess.Token,
		Expiry: uint32(time.Now().Add(time.Duration(30) * time.Minute).Unix()),
	}
	f.AddCookie(hc)
	f.session_cookie = hc.Value
	return hc.Value, nil
}

// must be called after backend and before sending response to webbrowser
// (sets a cookie if required)
func (f *FProxy) add_session_cookie(response *h2gproxy.ServeResponse, serr error) (*h2gproxy.ServeResponse, error) {
	if serr != nil {
		return response, serr
	}
	ctx := f.ctx
	if ctx == nil {
		ctx = authremote.Context()
	}

	am := authremote.GetAuthManagerClient()
	if am == nil {
		fmt.Printf("could not get authmanager\n")
		return response, serr
	}
	c, err := f.req.Cookie(SESSION_COOKIE_NAME)
	if err == http.ErrNoCookie || ((err == nil) && (c == nil)) {
		sign_sess, err := am.CreateSession(ctx, &common.Void{})
		if err != nil {
			fmt.Printf("Could not get session: %s\n", utils.ErrorString(err))
			return response, serr
		}
		f.session = sign_sess
		sess := &au.Session{}
		err = utils.UnmarshalBytes(sign_sess.Session, sess)
		if err != nil {
			fmt.Printf("Invalid session thing: %s\n", err)
			return response, serr
		}

		f.AddCookie(&h2gproxy.Cookie{
			Name:   SESSION_COOKIE_NAME,
			Value:  sess.Token,
			Expiry: uint32(time.Now().Add(time.Duration(30) * time.Minute).Unix()),
		})
		return response, serr
	} else if err != nil {
		// for a reason other than Not-exists, we could not get the cookie:
		fmt.Printf("failed to get session cookie: %s\n", utils.ErrorString(err))
		return response, serr
	}
	if c == nil {
		fmt.Printf("no cookie and weird error. err=%s!\n", err)
		return response, serr
	}
	// we got a cookie (to be fair, this would be better executer at the BEGINNING of the request)
	sign_sess, err := am.KeepAliveSession(ctx, &au.SessionToken{Token: c.Value})
	if err != nil {
		fmt.Printf("Failed to keep session alive: %s\n", utils.ErrorString(err))
	}
	f.session = sign_sess
	return response, serr
}
func (f *FProxy) with_session_cookie(response *h2gproxy.ServeResponse, err error) (*h2gproxy.ServeResponse, error) {
	f.add_session_cookie(response, err)
	return response, err
}
