package httplogger

import (
	"flag"
	"fmt"
	"sync"
	"time"

	pb "golang.conradwood.net/apis/httpkpi"
	"golang.conradwood.net/go-easyops/client"
	"golang.conradwood.net/go-easyops/tokens"
)

// static variables for flag parser
var (
	debug           = flag.Bool("debug_http_kpi_logger", false, "debug the http kpi logger")
	enable_http_log = flag.Bool("enable_http_kpi_logger", false, "enable http kpi logging")
	kpiClient       pb.HTTPKPITrackerClient
)

type QueueEntry struct {
	sent       bool
	logRequest *pb.NewCallRequest
}
type AsyncLogQueue struct {
	lock           sync.Mutex
	entries        []*QueueEntry
	flushables     []*QueueEntry
	lastErrPrinted time.Time
	MaxQueueSize   int
	DialFailures   int
}

func (a *AsyncLogQueue) LogHTTP(ncr *pb.NewCallRequest) {
	if !*enable_http_log {
		return
	}
	if *debug {
		fmt.Printf("LogHTTP: %#v\n", ncr)
	}
	qe := QueueEntry{sent: false,
		logRequest: ncr,
	}
	a.lock.Lock()
	a.entries = append(a.entries, &qe)
	a.lock.Unlock()
}

func (a *AsyncLogQueue) Flush() error {
	var lasterr error

	if len(a.entries) == 0 && len(a.flushables) == 0 {
		// save ourselves fro dialing and stuff
		return nil
	}
	if *debug {
		fmt.Printf("entries: %d, flushables: %d\n", len(a.entries), len(a.flushables))
	}
	// copy stuff from entries to flushables
	// we do double-buffering so we can release the lock
	// quickly (we're blocking clients serving the hot-path
	// while we hold the lock!)
	a.lock.Lock()
	// limit the flushables array to maximum queue size
	// (limiting the amount of RAM we're going to consume
	// e.g. in case the logservice is borken
	if (len(a.flushables) + len(a.entries)) > a.MaxQueueSize {
		fmt.Printf("Warning - httplogger Queue size of %d exceeded. discarded %d entries (%d dialfailures)\n", a.MaxQueueSize, len(a.flushables), a.DialFailures)
		a.flushables = a.entries
	} else {
		for _, f := range a.entries {
			a.flushables = append(a.flushables, f)
		}
		// moved the entries to flushables...
		a.entries = a.entries[:0]
	}
	a.lock.Unlock()
	retries := 5
	for {
		lasterr = nil
		for _, qe := range a.flushables {
			if qe.sent {
				continue
			}
			ctx := tokens.ContextWithToken()
			if kpiClient == nil {
				conn := client.Connect("httpkpi.HTTPKPITracker")
				kpiClient = pb.NewHTTPKPITrackerClient(conn)
			}

			_, err := kpiClient.NewCall(ctx, qe.logRequest)
			if err != nil {
				if time.Since(a.lastErrPrinted) > (10 * time.Second) {
					fmt.Printf("Failed to send log: %s\n", err)
					a.lastErrPrinted = time.Now()
				}
				lasterr = err
			} else {
				qe.sent = true
			}
		}
		if lasterr == nil {
			break
		}
		retries--
		if retries == 0 {
			//clear down queue after retries have been exceeded to prevent stuck lq entries.
			failedLogEnteries := ""
			for _, qe := range a.flushables {
				failedLogEnteries += "[ Remote Host= " + qe.logRequest.RemoteHost + ", Request URL=	" + qe.logRequest.RequestURL + "] "
			}
			errMsg := fmt.Sprintf("Failed to send httpkpis. failed entries={%v} last error: %s", failedLogEnteries, lasterr)
			//truncate queue
			a.flushables = a.flushables[:0]
			return fmt.Errorf(errMsg)
		}
	}
	a.flushables = a.flushables[:0]
	return nil
}

func NewAsyncLogQueue() (*AsyncLogQueue, error) {
	alq := &AsyncLogQueue{MaxQueueSize: 5000}
	t := time.NewTicker(2 * time.Second)
	go func(a *AsyncLogQueue) {
		for range t.C {
			err := a.Flush()
			if err != nil {
				fmt.Printf("Unable to process all Log Queue Entries: %s\n", err)
			}
		}
	}(alq)
	return alq, nil
}
