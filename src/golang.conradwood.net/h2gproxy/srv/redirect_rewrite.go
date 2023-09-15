package srv

import (
	"fmt"
	"strings"
)

func (h *HTTPForwarder) IsRedirectMatcher() bool {
	if len(h.def.RedirectRewrites) == 0 {
		return false
	}
	return true
}
func RedirectRewrite(f *FProxy) {
	u := f.FullURL()
	fmt.Printf("inbound url: \"%s\"\n", u)
	for _, rr := range f.hf.def.RedirectRewrites {
		ou := u
		u = strings.ReplaceAll(u, rr.MatchString, rr.ReplaceWith)
		if u != ou && rr.SetHost != "" {
			u = strings.TrimPrefix(u, "http://")
			u = strings.TrimPrefix(u, "https://")
			idx := strings.Index(u, "/")
			u = u[idx:]
			u = strings.TrimPrefix(u, "/")
			fmt.Printf("u without host: \"%s\"\n", u)
			u = "https://" + rr.SetHost + "/" + strings.TrimPrefix(u, "/")
		}
	}
	q := f.req.URL.RequestURI() // everything after the host (inc path)
	idx := strings.Index(q, "?")
	if idx != -1 {
		q = q[idx:]
		u = u + q
	}
	fmt.Printf("redirecting to: \"%s\"\n", u)
	f.RedirectTo(u, false)
}
