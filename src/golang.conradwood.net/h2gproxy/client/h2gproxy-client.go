package main

import (
	"context"
	"flag"
	"fmt"
	"golang.conradwood.net/apis/common"
	pb "golang.conradwood.net/apis/h2gproxy"
	ar "golang.conradwood.net/go-easyops/authremote"
	"golang.conradwood.net/go-easyops/tokens"
	"golang.conradwood.net/go-easyops/utils"
	"golang.conradwood.net/h2gproxy/shared"
	"os"
)

// static variables for flag parser
var (
	cons       = flag.Bool("tcp_connections", false, "show tcp connections")
	prober_on  = flag.Bool("prober_on", false, "switch probers on")
	prober_off = flag.Bool("prober_off", false, "switch probers on")
	showHosts  = flag.Bool("show_hosts", false, "show known hosts")
	showConfig = flag.Bool("show_config", false, "show config file")
	cfgfile    = flag.String("config_file", "", "Initial and optional configfile to read on startup")
	full       = flag.Bool("full", false, "show full config file")
	lbc        pb.H2GProxyServiceClient
)

func main() {
	var err error
	flag.Parse()
	lbc = pb.GetH2GProxyServiceClient()
	ctx := tokens.ContextWithToken()
	if *cons {
		showConnections()
		os.Exit(0)
	}
	if *prober_on {
		configProber(ctx, true)
	}
	if *prober_off {
		configProber(ctx, false)
	}
	if *cfgfile != "" {
		err = shared.SubmitClient(ctx, lbc, *cfgfile, shared.Httpdef{})
		if err != nil {
			fmt.Printf("Failed to read initial config %s: %s\n", *cfgfile, err)
			os.Exit(10)
		}
	}
	if *showConfig {
		show()
	}
	if *showHosts {
		show_hosts()
	}
	fmt.Printf("Done\n")
}
func show() {
	cfg, err := lbc.GetConfig(tokens.ContextWithToken(), &common.Void{})
	utils.Bail("failed to get config", err)
	for _, c := range cfg.Config {
		fmt.Printf("[%2d] %s\n", c.Api, c.URLPath)
		if *full {
			fmt.Printf("%#v\n", c)
		}
	}
}
func show_hosts() {
	hl, err := lbc.GetKnownHosts(tokens.ContextWithToken(), &common.Void{})
	utils.Bail("failed to get known hosts", err)
	format := "%30s %5v %5v %5v\n"
	fmt.Printf(format, "Hostname", "Cert", "http", "https")
	for _, h := range hl.Hosts {
		fmt.Printf(format, h.Hostname, h.GotCertificate, h.ServedHTTP, h.ServedHTTPS)
	}
}
func configProber(ctx context.Context, status bool) {
	req := &pb.ConfigureProberRequest{ProberBackend: status}
	_, err := lbc.ConfigureProber(ctx, req)
	utils.Bail("failed to configure prober", err)

}
func showConnections() {
	ctx := ar.Context()
	fmt.Printf("Showing tcp connections...\n")
	tsl, err := lbc.GetTCPSessions(ctx, &common.Void{})
	utils.Bail("failed to get sessions", err)
	for _, s := range tsl.Sessions {
		fmt.Printf("Session : %s:%d - %s:%d <=> %s:%d - %s:%d\n",
			s.PeerHost, s.PeerPort, "h2gproxy", s.InboundPort,
			"h2gproxy", s.ProxyOutboundPort, s.ProxyTargetHost, s.ProxyTargetPort)
	}
}
