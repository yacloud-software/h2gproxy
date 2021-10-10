package probe

import (
	"golang.conradwood.net/go-easyops/http"
)

func isWebLogin(hr *http.HTTPResponse) bool {

	for _, h := range hr.AllHeaders() {
		if h.Name == "weblogin" && h.Value == "true" {
			return true
		}
		//	fmt.Printf("            Received Header: %s=%s\n", h.Name, h.Value)
	}
	return false
}
