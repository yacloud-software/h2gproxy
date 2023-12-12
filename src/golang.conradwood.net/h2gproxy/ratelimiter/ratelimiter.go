package ratelimiter

import (
	"flag"
	"fmt"
	"sync"
	"time"
)

var (
	stall_clients = flag.Bool("ratelimiter_stall", false, "if true, stall clients before returning 429")
)

type Limiter struct {
	sync.Mutex
	// maximum amount of time we stall a client in the hope that a slot becomes available
	MaxStall time.Duration
	// if we're less than that, we won't limit
	AllowedClients int
	// the back-queue... if we have more clients than that waiting we'll return immediately instead of stalling
	AllowedWaitingClients int
	currentClients        int //How many clients are currently processing
	currentWaiting        int // how many clients are currently waiting to be processed?
	wait_chan             chan bool
}

func NewLimiter() *Limiter {
	res := &Limiter{
		wait_chan:             make(chan bool, 30),
		AllowedClients:        50,
		AllowedWaitingClients: 100,
		MaxStall:              time.Duration(3) * time.Second,
	}
	return res
}

func (l *Limiter) RequestStart() bool {
	l.Lock()
	if l.currentClients < l.AllowedClients {
		l.currentClients++
		l.Unlock()
		return true
	}
	l.Unlock()
	if !*stall_clients {
		return false
	}

	l.Lock()
	if l.currentWaiting >= l.AllowedWaitingClients {
		// too many waiting already
		l.Unlock()
		return false
	}
	l.currentWaiting++
	l.Unlock()

	started := time.Now()
	for {
		select {
		case <-l.wait_chan:
			// continue because something has finished
		case <-time.After(l.MaxStall / 3):
			// timeout
		}
		// try to lock again,
		l.Lock()
		if l.currentClients < l.AllowedClients {
			l.currentClients++
			l.currentWaiting--
			l.Unlock()
			return true
		}
		l.Unlock()
		if time.Since(started) >= l.MaxStall {
			break
		}
	}
	l.Lock()
	l.currentWaiting--
	l.Unlock()
	return false
}
func (l *Limiter) RequestFinish() {
	l.Lock()
	l.currentClients--
	if l.currentClients < 0 {
		l.currentClients = 0
	}
	l.Unlock()
	if !*stall_clients {
		return
	}
	select {
	case l.wait_chan <- true:
		// sent
	default:
		// not sent
	}
}

func (l *Limiter) Status() string {
	return fmt.Sprintf("Allowed: %d, AllowedWaiting: %d, Current: %d", l.AllowedClients, l.AllowedWaitingClients, l.currentClients)
}
