package srv

import (
	"flag"
	"strings"

	"golang.conradwood.net/go-easyops/auth"
)

var (
	use_new_auth_handler = flag.Bool("use_new_auth_handler", true, "if false, disable new auth handler")
)

// returns true if request can proceed
// this encapsulates all the myriad ways of authenticating to h2gproxy
// once it returns, the authentication information (if any) from the request was parsed and any
// user authentication has been noted in fproxy.
// if no user was found in the request AND request configured to require authentication,
// this will trigger authentication.
func (f *FProxy) handle_auth_if_required() bool {
	if !*use_new_auth_handler {
		return true
	}
	// always try to parse user details from request
	a, err := json_auth(f) // always check if we got auth stuff
	if err != nil {
		f.Printf("failed to jsonauth for usercontext: %s\n", err)
		return false
	}
	f.authResult = a
	// needs auth? if so check if authenticated and if not trigger auth
	if !f.NeedsAuth() {
		return true
	}

	// we need auth per config
	f.Debugf("needs authentication per config\n")

	if !a.Authenticated() {
		// no auth found in request
		f.TriggerAuthentication()
		return false
	}
	// do we need to parse headers and stuff here?
	su := a.SignedUser()
	if su == nil {
		// should not happen. Authenticated, but no user?
		f.Printf("Authenticated - but no signed user. This is a bug\n")
		return false
	}
	f.signeduser = su
	user := a.User()
	if user == nil {
		// should not happen. Authenticated, but no user?
		f.Printf("Authenticated - but no user. This is a bug\n")
		return false
	}
	f.unsigneduser = user

	if len(f.hf.def.Groups) > 0 { // no group configured means ANY group is allowed
		if !isUserInGroup(f.unsigneduser, f.hf.def.Groups) {
			gs := strings.Join(f.hf.def.Groups, ", ")
			f.Printf("User %s is not in any (%s) of the groups for path %s\n", auth.UserIDString(f.unsigneduser), gs, f.RequestedPath())
			f.SetStatus(403) // access denied
			return false
		}
	}
	return true

}
