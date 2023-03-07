package srv

import (
	"context"
	"flag"
	"fmt"
	//au "golang.conradwood.net/apis/auth"
	//	"golang.conradwood.net/apis/common"
	"golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/go-easyops/authremote"
	"golang.conradwood.net/go-easyops/common"
	"golang.conradwood.net/go-easyops/utils"
	"golang.yacloud.eu/apis/session"
	"golang.yacloud.eu/apis/sessionmanager"
	//	"net/http"
	"time"
)

const (
	SESSION_COOKIE_NAME = "Yei0neez1ohyohnith6iger6Oogexoo_sescook"
)

var (
	debug_session = flag.Bool("debug_session", false, "debug session stuff")
)

func (f *FProxy) xisSessionValid(ctx context.Context, session string) (bool, *session.Session) {
	if *debug_session {
		fmt.Printf("Session - isSessionValid()\n")
	}
	if session == "" {
		return false, nil
	}
	st := &sessionmanager.SessionToken{Token: session}
	res, err := sessionmanager.GetSessionManagerClient().KeepAliveSession(ctx, st)
	if err != nil {
		fmt.Printf("Failed to validate session: %s\n", err)
		return false, nil
	}
	if !res.IsValid {
		if *debug_session {
			fmt.Printf("Session invalid (%s)\n", session)
		}
		return false, nil
	}
	if *debug_session {
		fmt.Printf("Session valid\n")
	}
	return true, res.Session
	/*
			am := authremote.GetAuthManagerClient()
			if am == nil {
				fmt.Printf("could not get authmanager\n")
				return false
			}
			if ctx == nil {
				return false
			}
			sign_sess, err := am.KeepAliveSession(ctx, &au.KeepAliveSessionRequest{Token: session, User: f.signeduser})
			f.session = sign_sess
			if err != nil {
				fmt.Printf("session not valid: %s\n", err)
				return false
			}
		return true
	*/
}

// get it from cookie or parameters and return it (or nil)
func (f *FProxy) get_session_from_request(ctx context.Context) *session.Session {
	sess_para := f.QueryValues()["sess"]
	if sess_para != "" {
		t, sess := f.xisSessionValid(ctx, sess_para)
		if t {
			return sess
		}
	}
	c, err := f.req.Cookie(SESSION_COOKIE_NAME)
	if *debug_session && (c == nil || c.Value == "") {
		fmt.Printf("Session - no session cookie received\n")
	}
	if err == nil && c != nil && c.Value != "" {
		t, sess := f.xisSessionValid(ctx, c.Value)
		if t {
			return sess
		}
	}

	return nil

}

// get or create a session token
// called (or should be called) before calling a backend
func (f *FProxy) GetSessionToken() (string, error) {
	if *debug_session {
		fmt.Printf("Session - GetSessionToken()()\n")
	}
	ctx := f.ctx
	if ctx == nil {
		ctx = authremote.Context()
	}
	if f.session != nil {
		return f.session.SessionID, nil
	}
	sess := f.get_session_from_request(ctx)

	if sess != nil {
		f.session = sess
		if *debug_session {
			fmt.Printf("Session - got valid session (%s) from cookie\n", print_session_id(sess.SessionID))
		}
		return sess.SessionID, nil
	}

	nsr := f.GetNewSessionRequest()
	sr, err := sessionmanager.GetSessionManagerClient().NewSession(ctx, nsr)
	if err != nil {
		fmt.Printf("Could not get session: %s\n", utils.ErrorString(err))
		return "", err
	}
	f.session = sr.Session
	hc := &h2gproxy.Cookie{
		Name:   SESSION_COOKIE_NAME,
		Value:  f.session.SessionID,
		Expiry: uint32(time.Now().Add(time.Duration(30) * time.Minute).Unix()),
	}
	f.AddCookie(hc)
	if *debug_session {
		fmt.Printf("Session - added new session (%s)\n", print_session_id(f.session.SessionID))
	}

	return f.session.SessionID, nil

}

// must be called after backend and before sending response to webbrowser
// (sets a cookie if required)
func (f *FProxy) add_session_cookie(response *h2gproxy.ServeResponse, serr error) (*h2gproxy.ServeResponse, error) {
	if *debug_session {
		fmt.Printf("Session - add_session_cookie()()\n")
	}
	if serr != nil {
		return response, serr
	}
	if f.session == nil {
		panic("no session to add")
	}
	u := f.GetUser()
	if u != nil {
		ctx := f.ctx
		u2s := &sessionmanager.User2SessionRequest{
			Session: f.session,
			User:    u,
		}
		sr, err := sessionmanager.GetSessionManagerClient().User2Session(ctx, u2s)
		if err != nil {
			if *debug_session {
				fmt.Printf("session - update failed (%s)\n", err)
			}
			return nil, err
		}
		if sr != nil && !sr.IsValid {
			panic("session became invalid whilst processing request")
		}
	}

	f.AddCookie(&h2gproxy.Cookie{
		Name:   SESSION_COOKIE_NAME,
		Value:  f.session.SessionID,
		Expiry: uint32(time.Now().Add(time.Duration(120) * time.Minute).Unix()),
	})
	return response, serr
}
func (f *FProxy) with_session_cookie(response *h2gproxy.ServeResponse, err error) (*h2gproxy.ServeResponse, error) {
	f.add_session_cookie(response, err)
	return response, err
}

func (f *FProxy) GetNewSessionRequest() *sessionmanager.NewSessionRequest {
	su := f.signeduser
	u := common.VerifySignedUser(su)
	us := ""
	un := ""
	ue := ""
	if u != nil {
		us = u.ID
		un = fmt.Sprintf("%s %s", u.FirstName, u.LastName)
		ue = u.Email
	}
	nsr := &sessionmanager.NewSessionRequest{
		IPAddress:   f.PeerIP(),
		UserAgent:   f.GetUserAgent(),
		BrowserID:   "",
		UserID:      us,
		Username:    un,
		Useremail:   ue,
		TriggerHost: f.GetHeader("host"),
	}
	return nsr
}
func print_session_id(id string) string {
	if len(id) < 15 {
		return id
	}
	return id[:15]
}
