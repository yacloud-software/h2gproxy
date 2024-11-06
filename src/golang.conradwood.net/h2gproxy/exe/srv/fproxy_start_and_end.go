package srv

import (
	"flag"
	"fmt"
	"sync"

	"golang.conradwood.net/go-easyops/common"
	"golang.conradwood.net/go-easyops/utils"
	"golang.yacloud.eu/apis/session"
)

var (
	single_thread      = flag.Bool("single_thread", false, "if true only one thread will process http requests")
	single_thread_lock sync.Mutex
	cur_proxies        []*FProxy
	cur_proxies_lock   sync.Mutex
)

func init() {
	common.RegisterInfoProvider("fproxy-list", fproxy_list_info_provider)
}
func fproxy_list_info_provider() []*common.InfoValue {
	var res []*common.InfoValue
	cur_proxies_lock.Lock()
	for _, f := range cur_proxies {
		iv := &common.InfoValue{
			Name:  fmt.Sprintf("FProxy #%d, Created=%s, peerip=%s, config=%s, path=%s", f.print_counter, utils.TimeString(f.Started), f.PeerIP(), f.ConfigName(), f.RequestedPath()),
			Value: 1.0,
		}
		res = append(res, iv)
	}
	cur_proxies_lock.Unlock()
	return res
}
func StartRequest(f *FProxy) {
	cur_proxies_lock.Lock()
	cur_proxies = append(cur_proxies, f)
	cur_proxies_lock.Unlock()
	if !*single_thread {
		return
	}
	single_thread_lock.Lock()
	fmt.Printf("--------------------------- STARTED ----------------\n")
	printSession(f.session)
}

func EndRequest(f *FProxy) {
	cur_proxies_lock.Lock()
	for i, cf := range cur_proxies {
		if cf == f { // assumed to be pointer identical
			// remove element
			cur_proxies[i] = cur_proxies[len(cur_proxies)-1]
			cur_proxies = cur_proxies[:len(cur_proxies)-1]
			break
		}
	}
	cur_proxies_lock.Unlock()
	if !*single_thread {
		return
	}
	printSession(f.session)
	fmt.Printf("--------------------------- FINISHED ----------------\n")
	single_thread_lock.Unlock()

}

func printSession(s *session.Session) {
	if s == nil {
		fmt.Printf("No session\n")
		return
	}
	fmt.Printf("Session: %s\n", s.SessionID)
}
