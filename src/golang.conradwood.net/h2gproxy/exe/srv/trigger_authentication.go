package srv

/*
if it's a known CLI, then send basic-auth request, otherwise redirect to weblogin
*/
func (f *FProxy) TriggerAuthentication() {
	if f.IsKnownCLITool() {
		f.SetStatus(401)
		f.SetHeader("WWW-Authenticate", `Basic realm="Login"`)
		f.Write([]byte("401 - authentication required"))
		return
	}
	f.WebLogin()

}
