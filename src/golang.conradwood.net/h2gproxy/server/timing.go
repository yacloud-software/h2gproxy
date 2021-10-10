package main

import (
	"flag"
	"fmt"
	"time"
)

var (
	debug_timing = flag.Bool("print_timing_live", false, "if true, print timing as and when timings are taken")
)

type Timing struct {
	name  string
	start time.Time
	end   time.Time
}

func NewTiming(name string) *Timing {
	return &Timing{name: name, start: time.Now()}
}
func (t *Timing) Done() {
	t.end = time.Now()
	if *debug_timing {
		fmt.Printf("[timing] completed %s, result: %v\n", t.name, t.end.Sub(t.start))
	}
}
func (t *Timing) IsValid() bool {
	if t.end.IsZero() {
		return false
	}
	return !t.start.IsZero()
}
