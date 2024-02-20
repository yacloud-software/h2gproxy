package iphelper

import (
	"fmt"
	"strconv"
	"strings"
)

// endpoint, such as '1.1.1.1:53' or ipv6 or so
// returns a network ip, a port, version (4 or 6)
func ParseEndpoint(endpoint string) (string, uint32, int, error) {
	if len(endpoint) < 4 {
		return "", 0, 0, fmt.Errorf("\"%s\" is not a valid ip", endpoint)
	}
	ct := strings.Count(endpoint, ":")
	if ct == 1 {
		idx := strings.Index(endpoint, ":")
		ip := endpoint[:idx]
		port, err := strconv.Atoi(endpoint[idx+1:])
		if err != nil {
			return "", 0, 0, err
		}
		return ip, uint32(port), 4, nil
	}

	if ct == 0 {
		return endpoint, 0, 4, nil
	}

	// must be ip6:
	if endpoint[0] != '[' {
		// without port
		return endpoint, 0, 6, nil
	}

	ep := endpoint[1:]
	idx := strings.Index(ep, "]")
	if idx == -1 {
		return "", 0, 0, fmt.Errorf("not a valid ipv6 with port: \"%s\"", endpoint)
	}
	ip := ep[:idx]
	port, err := strconv.Atoi(ep[idx+2:]) // skip "]" and ":"
	if err != nil {
		return "", 0, 0, err
	}
	return ip, uint32(port), 6, nil
}
