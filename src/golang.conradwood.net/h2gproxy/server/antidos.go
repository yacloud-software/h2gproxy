package main

import (
	"context"
	"flag"
	"fmt"
	"golang.conradwood.net/apis/antidos"
	"golang.conradwood.net/go-easyops/authremote"
	"golang.conradwood.net/go-easyops/utils"
	"net"
	"net/http"
)

var (
	check_antidos = flag.Bool("antidos_check_each_request", false, "if true check each request with antidos before passing it on")
)

// all http requests should be send here first.
// if it returns true the request was intercepted and handled by AntiDOS and no further processing shold occur
func AntiDOS_HTTPHandler(w http.ResponseWriter, r *http.Request, port int) bool {
	if !*check_antidos {
		return false
	}
	ip := r.RemoteAddr
	ip, _, err := net.SplitHostPort(ip)
	if err != nil {
		fmt.Printf("Cannot check ip \"%s\" - error parsing (%s)\n", ip, err)
		return false
	}
	fmt.Printf("Checking remoteaddr \"%s\"\n", ip)
	ctx := authremote.Context()
	b := AntiDOS_IsBlacklisted(ctx, ip)
	fmt.Printf("IP \"%s\" blacklisted? %v\n", ip, b)
	return false
}

// return true if antidos says it's blacklistest
func AntiDOS_IsBlacklisted(ctx context.Context, ip string) bool {
	if !*check_antidos {
		return false
	}
	req := &antidos.IPRequest{IP: ip}
	r, err := antidos.GetAntiDOSClient().IPStatus(ctx, req)
	if err != nil {
		fmt.Printf("Failed to check antidos: %s\n", utils.ErrorString(err))
		return false
	}
	if r.Blocked {
		return true
	}
	return false
}

func AntiDOS_BuildBlackListPage(ip string) []byte {
	s := `<html><body>
Your Request was blocked because we detected suspicious traffic from your IP Address (` + ip + `). Please retry again later.
</body>
</html>
`
	return []byte(s)
}
