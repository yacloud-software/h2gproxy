package httplogger

import (
	"sync"
)

var (
	reqctrlock sync.Mutex
	reqctr     uint64
)

func getNextReqCtr() uint64 {
	reqctrlock.Lock()
	reqctr++
	res := reqctr
	reqctrlock.Unlock()
	return res
}
