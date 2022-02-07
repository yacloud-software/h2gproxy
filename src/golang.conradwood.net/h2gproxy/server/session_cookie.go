package main

import (
	"fmt"
	au "golang.conradwood.net/apis/auth"
	"golang.conradwood.net/apis/common"
	"golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/go-easyops/authremote"
	"golang.conradwood.net/go-easyops/utils"
	"net/http"
)

const (
	SESSION_COOKIE_NAME = "Yei0neez1ohyohnith6iger6Oogexoox"
)

func (f *FProxy) add_session_cookie(response *h2gproxy.ServeResponse, serr error) (*h2gproxy.ServeResponse, error) {
	if serr != nil {
		return response, serr
	}
	c, err := f.req.Cookie(SESSION_COOKIE_NAME)
	if err == http.ErrNoCookie {
		tk, err := authremote.GetAuthManagerClient().CreateSession(f.ctx, &common.Void{})
		if err != nil {
			fmt.Printf("Could not get session: %s\n", utils.ErrorString(err))
			return response, serr
		}
		f.AddCookie(&h2gproxy.Cookie{
			Name:  SESSION_COOKIE_NAME,
			Value: tk.Token,
		})

	} else if err != nil {
		// for a reason other than Not-exists, we could not get the cookie:
		fmt.Printf("failed to get session cookie: %s\n", utils.ErrorString(err))
		return response, serr
	}
	// we got a cookie
	_, err = authremote.GetAuthManagerClient().KeepAliveSession(f.ctx, &au.SessionToken{Token: c.Value})
	if err != nil {
		fmt.Printf("Failed to keep session alive: %s\n", utils.ErrorString(err))
	}

	return response, serr
}
func (f *FProxy) with_session_cookie(response *h2gproxy.ServeResponse, err error) (*h2gproxy.ServeResponse, error) {
	f.add_session_cookie(response, err)
	return response, err
}
