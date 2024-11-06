package unistream

import (
	"golang.conradwood.net/h2gproxy/stream"
)

// returns true if request can proceed
func handle_auth_if_required(rd stream.RequestDetails) bool {
	// needs auth? if so check if authenticated and if not trigger auth
	if !rd.NeedsAuth() {
		return true
	}
	// do we need to parse headers and stuff here?
	ctx := rd.UserContext()
	user := auth.GetUser(ctx)
	if user == nil {
		rd.TriggerAuthentication()
		return false
	}
	// TODO: check groups

	rd.TriggerAuthentication()
	return false

}
