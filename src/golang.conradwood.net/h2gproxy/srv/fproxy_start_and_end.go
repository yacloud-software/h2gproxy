package srv

import (
	"flag"
	"fmt"
	"golang.yacloud.eu/apis/session"
	"sync"
)

var (
	single_thread      = flag.Bool("single_thread", false, "if true only one thread will process http requests")
	single_thread_lock sync.Mutex
)

func StartRequest(f *FProxy) {
	if *single_thread {
		single_thread_lock.Lock()
	}
	fmt.Printf("--------------------------- STARTED ----------------\n")
	printSession(f.session)
}

func EndRequest(f *FProxy) {
	printSession(f.session)
	fmt.Printf("--------------------------- FINISHED ----------------\n")
	if *single_thread {
		single_thread_lock.Unlock()
	}
}

func printSession(s *session.Session) {
	if s == nil {
		fmt.Printf("No session\n")
		return
	}
	fmt.Printf("Session: %s\n", s.SessionID)
}
