package main

/*
read an h2gproxy logfile (see logger)
*/
import (
	"flag"
	"fmt"
	"golang.conradwood.net/go-easyops/utils"
	"golang.conradwood.net/h2gproxy/httplogger/reader"
)

var (
	min_dur = flag.Duration("min_duration", 0, "set to a minimum duration to filter on")
)

func main() {
	flag.Parse()
	r, err := reader.NewReader(flag.Args()[0])
	utils.Bail("failed to open reader: %s\n", err)
	for {
		entry, err := r.Read()
		if err != nil {
			fmt.Printf("read error: %s\n", err)
			break
		}
		handleEntry(entry)
	}
}
func handleEntry(entry *reader.Entry) {
	if *min_dur != 0 && entry.Duration < *min_dur {
		return
	}
	//	fmt.Printf("Entry: %#v\n", entry)
	fmt.Printf("%05d %0.2fs %d %s %s\n", entry.ReqID, entry.Duration.Seconds(), entry.Code, entry.URL, entry.Message)
}
