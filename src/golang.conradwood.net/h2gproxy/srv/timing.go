package srv

import (
	"flag"
	"fmt"
	"golang.conradwood.net/go-easyops/prometheus"
	"time"
)

var (
	timdist = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "h2gproxy_req_timing_breakdown",
			Help: "V=1 UNIT-none DESC=counter increases by number of seconds for each timing",
		},
		[]string{"config", "timing"},
	)
	debug_timing = flag.Bool("print_timing_live", false, "if true, print timing as and when timings are taken")
	print_timing = flag.Bool("print_timing", false, "print timing information for each request")
)

func init() {
	prometheus.MustRegister(timdist)
}

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

// called at the end of each request
func processTimings(f *FProxy) {
	for _, t := range f.Timings {
		dur := t.end.Sub(t.start).Seconds()
		l := prometheus.Labels{"config": f.hf.def.ConfigName, "timing": t.name}
		timdist.With(l).Add(dur)
	}
	if !*print_timing {
		return
	}
	fmt.Printf("[timing] %d timings:\n", len(f.Timings))
	for _, t := range f.Timings {
		dur := t.end.Sub(t.start).Seconds()
		fmt.Printf("[timing] %s=%0.2f\n", t.name, dur)
	}
	fmt.Println()

}
