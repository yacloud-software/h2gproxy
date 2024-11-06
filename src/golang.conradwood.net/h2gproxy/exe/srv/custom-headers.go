package srv

import (
	//	"google.golang.org/grpc/codes"
	"fmt"
	"strings"

	au "golang.conradwood.net/apis/auth"
	"golang.conradwood.net/go-easyops/auth"
	"golang.conradwood.net/go-easyops/utils"
	"google.golang.org/grpc/status"
)

// given a context and a reply, this will insert headers
// indicating status etc
// (if it's not a guru user no sensitive headers will be added)
type ExtraInfo struct {
	Message string
	Error   error
}

// get a header from the list of headers the browser sent
func (f *FProxy) getBrowserHeader(header string) string {
	h := strings.ToLower(header)
	for k, v := range f.req.Header {
		if strings.ToLower(k) != h {
			continue
		}
		if len(v) == 0 {
			continue
		}
		return v[0]
	}
	return ""
}

// headers to return to the caller
func (f *FProxy) customHeaders(msg *ExtraInfo) {
	// non-sensitive headers
	orig := f.getBrowserHeader("origin")
	if orig == "" {
		f.SetHeader("Access-Control-Allow-Origin", "*")
	} else {
		f.SetHeader("Access-Control-Allow-Origin", orig)
	}
	f.SetHeader("Access-Control-Allow-Credentials", "true")
	f.SetHeader("X-LB-Platform", "YACLOUD.EU")
	f.SetHeader("X-LB-REQUESTID", f.GetRequestID())

	if f.unsigneduser == nil && f.signeduser == nil {
		if *debug {
			fmt.Printf("Custom-Headers: not inserted, no user.\n")
		}
		return
	}

	user := f.unsigneduser
	if user == nil {
		user = &au.User{}
		err := utils.UnmarshalBytes(f.signeduser.User, user)
		if err != nil {
			fmt.Printf("Invalid signed user: %s\n", err)
			return
		}
	}
	f.addHeader("Userid", user.ID)
	if !auth.IsRootUser(user) && (!IsDebugHeaderGroup(user)) {
		if *debug {
			fmt.Printf("Custom-Headers: not inserted, user \"%s\" not rootuser.\n", user.ID)
		}
		return
	}
	// sensitive headers (user != nil)

	// proxy ifo
	if f.proxyResponse != nil {
		f.addHeader("Backend-Result-String", f.proxyResponse.Status)
		f.addHeader("Backend-Result-Code", fmt.Sprintf("%d", f.proxyResponse.StatusCode))
	}
	f.addHeader("TargetHost", f.targetHost)

	// routing info
	if f.hf.def != nil {

	}
	// request stuff
	f.addHeader("Userid", user.ID)
	f.addHeader("Useremail", user.Email)
	if msg != nil && msg.Error != nil {
		m := "rpc error: code = Unknown desc ="
		fm := fmt.Sprintf("%s", msg.Error)
		if strings.HasPrefix(fm, m) {
			fm = fm[len(m):]
		}
		if *debug {
			fmt.Printf("Custom-Headers: header failure message: \"%s\"\n", fm)
		}
		f.addHeader("Failuremessage", fm)
		st := status.Convert(msg.Error)
		if st != nil {
			// grpc error (with extended information)
			message := st.Message()
			code := st.Code()
			f.addHeader("GRPC-Message", message)
			f.addHeader("GRPC-Code", fmt.Sprintf("%d", code))
			f.addHeader("GRPC-Code-Text", fmt.Sprintf("%v", code))
			det := st.Details()
			for i, d := range det {
				f.addHeader(fmt.Sprintf("DetailMessage-%d", i), fmt.Sprintf("%v", d))
			}
		}
	}
}

func (f *FProxy) addHeader(name string, value string) {
	// what follows is possibly the worst implementation
	// of http header escape & fix up ever written.
	// it appears that chrome has a limit of 80 chars of http headers
	// and god knows what other browsers think ;(
	// anyone finds a spec for http headers?
	// (except "ascii only" should work...)
	x := ""
	sp := false
	max_header_len := 80
	if strings.Contains(strings.ToLower(f.UserAgent()), "wget") {
		max_header_len = 1024
	}
	for i, s := range value {
		if s == '"' || s == ' ' || s == '\n' || s == '\r' {
			if sp {
				continue
			}
			s = ' '
			sp = true
		} else {
			sp = false
		}
		x = x + string(s)
		if i > max_header_len {
			break
		}

	}
	if x != value && *debug {
		fmt.Printf("Custom-Headers: New header value: \"%s\"\n", x)
	}
	f.SetHeader(fmt.Sprintf("X-LB-%s", name), x)
}

func IsDebugHeaderGroup(user *au.User) bool {
	if user == nil {
		if *debug {
			fmt.Printf("[debugheadergroup] no user\n")
		}
		return false
	}
	gc := getGlobalConfigSection()
	if gc == nil {
		return false
	}
	for _, ug := range user.Groups {
		for _, dhg := range gc.DebugHeaderGroups {
			if dhg == ug.ID {
				if *debug {
					fmt.Printf("[debugheadergroup] user group \"%s\" matched\n", ug.ID)
				}
				return true
			}
			if *debug {
				fmt.Printf("[debugheadergroup] user group \"%s\" does not match \"%s\"\n", ug.ID, dhg)
			}

		}
	}
	if *debug {
		fmt.Printf("[debugheadergroup] user does not deserve special headers\n")
	}
	return false
}
