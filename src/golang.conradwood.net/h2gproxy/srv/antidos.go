package srv

import (
	"context"
	"flag"
	"fmt"
	"golang.conradwood.net/apis/antidos"
	"golang.conradwood.net/go-easyops/authremote"
	"golang.conradwood.net/go-easyops/cache"
	"golang.conradwood.net/go-easyops/utils"
	"net"
	"net/http"
	"time"
)

var (
	check_antidos    = flag.Bool("antidos_check_each_request", true, "if true check each request with antidos before passing it on")
	antidos_debug    = flag.Bool("antidos_debug", false, "if true debug antidos")
	antidos_ip_cache = cache.New("antidos_ip_cache", time.Duration(1)*time.Minute, 1000)
)

type antidos_ip_cache_entry struct {
	blocked bool
}

// all http requests should be send here first.
// if it returns true the request was intercepted and handled by AntiDOS and no further processing shold occur
func AntiDOS_HTTPHandler(w http.ResponseWriter, r *http.Request, port int) bool {
	if !*check_antidos {
		return false
	}
	ip := r.RemoteAddr
	ip, _, err := net.SplitHostPort(ip)
	if err != nil {
		fmt.Printf("[antidos] Cannot check ip \"%s\" - error parsing (%s)\n", ip, err)
		return false
	}
	if *antidos_debug {
		fmt.Printf("[antidos] Checking remoteaddr \"%s\"\n", ip)
	}
	ctx := authremote.Context()
	b := AntiDOS_IsBlacklisted(ctx, ip)
	if *antidos_debug {
		fmt.Printf("[antidos] IP \"%s\" blacklisted? %v\n", ip, b)
	}
	if !b {
		return false
	}
	page := AntiDOS_BuildBlackListPage(ip)
	w.Header()["content-type"] = []string{"text/html"}
	w.Write(page)
	return true
}

// return true if antidos says it's blacklistest
func AntiDOS_IsBlacklisted(ctx context.Context, ip string) bool {
	if !*check_antidos {
		return false
	}
	var aic *antidos_ip_cache_entry
	o := antidos_ip_cache.Get(ip)
	if o != nil {
		aic = o.(*antidos_ip_cache_entry)
	}

	if aic != nil {
		return aic.blocked
	}

	req := &antidos.IPRequest{IP: ip}
	r, err := antidos.GetAntiDOSClient().IPStatus(ctx, req)
	if err != nil {
		fmt.Printf("[antidos] Failed to check antidos: %s\n", utils.ErrorString(err))
		return false
	}
	aic = &antidos_ip_cache_entry{blocked: r.Blocked}
	antidos_ip_cache.Put(ip, aic)
	if r.Blocked {
		return true
	}
	return false
}

func AntiDOS_BuildBlackListPage(ip string) []byte {
	if *antidos_debug {
		fmt.Printf("[antidos] Building blacklist page for ip \"%s\"\n", ip)
	}
	s := `<html><body>
Your Request was blocked because we detected suspicious traffic from your IP Address (` + ip + `). Please retry again later.
</body>
</html>
`
	return []byte(s)
}
