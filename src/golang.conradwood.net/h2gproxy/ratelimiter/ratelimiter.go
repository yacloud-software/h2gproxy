package ratelimiter

import (
	"time"
)

type Limiter struct {
	// maximum amount of time we stall a client in the hope that a slot becomes available
	MaxStall time.Duration
	// if we're less than that, we won't limit
	AllowedClients int
	// the back-queue... if we have more clients than that waiting we'll return immediately instead of stalling
	AllowedWaitingClients int
	//How many clients are currently processing
	currentClients int
}

func NewLimiter() *Limiter {
	res := &Limiter{
		AllowedClients:        30,
		AllowedWaitingClients: 10,
		MaxStall:              time.Duration(1) * time.Second,
	}
	return res
}

func (l *Limiter) RequestStart() bool {
	if l.currentClients < l.AllowedClients {
		l.currentClients++
		return true
	}
	return false
}
func (l *Limiter) RequestFinish() {
	l.currentClients--
	if l.currentClients < 0 {
		l.currentClients = 0
	}
}
