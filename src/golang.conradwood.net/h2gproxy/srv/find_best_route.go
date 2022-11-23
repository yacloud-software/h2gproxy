package srv

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// based on a given request find the best match
func findBestMatch(req *http.Request, proto string) *HTTPForwarder {
	routeLock.Lock()
	defer routeLock.Unlock()
	var res *HTTPForwarder
	for _, r := range routes {
		if !doesMatch(req, r, proto) {
			continue
		}
		if r.isAbsolute {
			// if it does match an absolute one, return it immediately
			res = r
			break
		}
		if *debug_match {
			fmt.Printf("possible match: url %s matches %s\n", req.URL, r.String())
		}
		if res == nil {
			res = r
			continue
		}
		if len(res.def.URLHostname) > len(r.def.URLHostname) {
			// if we got one with match on url, then prefer that
			continue
		} else if len(res.def.URLHostname) < len(r.def.URLHostname) {
			// if this one matches a longer portion of the url, use it
			res = r
			continue
		}
		if len(r.def.ProtocolRequired) > len(res.def.ProtocolRequired) {
			res = r
		}
		if len(r.def.URLPath) > len(res.def.URLPath) {
			res = r
		}
		if isPrivateIP(req.RemoteAddr) && (r.def.RFC1918Only && !res.def.RFC1918Only) {
			res = r
		}

		if len(r.def.URLPath) == len(res.def.URLPath) {
			if (res.def.URLHostname == "") && (r.def.URLHostname != "") {
				res = r
			}
		}

	}
	if *debug_match {
		fmt.Printf("final matchresult: url %s matches %s\n", req.URL, res.String())
	}
	return res
}

// returns true if this request matches this forwarder
// e.g. returns false if url/user/group stuff doesn't match
// as per needauth - it will return true even if user is not authenticated (yet)
// proto should be http/https (will be mached against "protocolrequired" field in config
func doesMatch(r *http.Request, hf *HTTPForwarder, proto string) bool {
	p := r.URL.Path
	var hostName string
	var port string
	var err error
	ip := r.RemoteAddr
	if hf.def.RFC1918Only && (!isPrivateIP(ip)) {
		if *debug_match {
			fmt.Printf("Request does not match. Private ip mismatch: %s [%v])\n", ip, isPrivateIP(ip))
		}
		return false
	}
	if (hf.def.ProtocolRequired != "") && (hf.def.ProtocolRequired != proto) {
		if *debug_match {
			fmt.Printf("Request does not match protocol %s (vs %s)\n", hf.def.ProtocolRequired, proto)
		}
		return false
	}
	if !strings.Contains(r.Host, ":") {
		hostName = r.Host
		port = "80"
		err = nil
	} else {
		hostName, port, err = net.SplitHostPort(r.Host)
	}
	if err != nil {
		fmt.Printf("Error splitting %s (port %s): %s\n", r.Host, port, err)
		return false
	}

	if hf.def.Api == 5 {
		// fuzzy urlhostname proxy  match
		if (hf.def.URLHostname != "") && (!strings.HasSuffix(hostName, hf.def.URLHostname)) && !fuzzy_match(hf.def.URLHostname, hostName) {
			if *debug_match {
				fmt.Printf("hostname \"%s\" does not fuzzy match %s\n", hostName, hf.def.URLHostname)
			}
			return false
		}

	} else {
		// strict urlhostname match
		if (hf.def.URLHostname != "") && (hf.def.URLHostname != hostName) && !fuzzy_match(hf.def.URLHostname, hostName) {
			if *debug_match {
				fmt.Printf("hostname %s does not match %s\n", hf.def.URLHostname, r.Host)
			}
			return false
		}
	}
	if !strings.HasPrefix(p, hf.def.URLPath) {
		if *debug_match {
			fmt.Printf("url %s does not match %s\n", p, hf.def.URLPath)
		}
		return false
	}

	if *debug_match {
		fmt.Printf("Match: %v\n", hf.def)
	}
	return true
}

// do a fuzzy match, e.g. www.* against www.yacloud.eu
func fuzzy_match(match, hostname string) bool {
	if !strings.Contains(match, "*") {
		return false
	}
	if len(match) == 0 || len(hostname) == 0 {
		return false
	}
	// two cases: leading * or trailing *
	if match[0] == '*' {
		// leading
		return strings.HasSuffix(hostname, match[1:])
	} else if match[len(match)-1] == '*' {
		//trailing
		return strings.HasPrefix(hostname, match[:len(match)-1])
	} else {
		fmt.Printf("Match \"%s\" not support, asterisk must be either leading or trailing\n", match)
	}
	return false
}
