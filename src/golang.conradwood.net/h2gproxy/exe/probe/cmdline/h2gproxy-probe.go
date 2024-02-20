package main

// probe the h2gproxy
import (
	"flag"
	"fmt"
	"golang.conradwood.net/go-easyops/tokens"
	"golang.conradwood.net/h2gproxy/probe"
	"os"
)

var (
	email    = flag.String("prober_email", "", "email address to authenticate with")
	password = flag.String("prober_password", "", "password to authenticate with")
)

func main() {
	flag.Parse()
	probe.Start()
	p := probe.Probe{
		Host:           "localhost",
		UserToken:      tokens.GetUserTokenParameter(),
		ProberEmail:    *email,
		ProberPassword: *password,
	}
	failed := false
	for {
		results := p.AllTests()
		for _, r := range results {
			failed = failed || r.Failed()
			s := r.String()
			if len(s) > 170 {
				s = s[:170] + "..."
			}
			fmt.Println(s)
		}
		break
	}
	if failed {
		os.Exit(10)
	}
	os.Exit(0)

}
