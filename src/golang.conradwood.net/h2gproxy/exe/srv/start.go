package srv

// this thing shall forward connections to deployed
// services
// we start with "tcp" and then move to http
// and more sophisticated url matching and cookie
// handling

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	apb "golang.conradwood.net/apis/auth"
	"golang.conradwood.net/apis/common"
	pb "golang.conradwood.net/apis/h2gproxy"
	us "golang.conradwood.net/apis/usagestats"
	"golang.conradwood.net/go-easyops/client"
	"golang.conradwood.net/go-easyops/server"
	"golang.conradwood.net/go-easyops/utils"
	"golang.conradwood.net/h2gproxy/probe"
	proxynone "golang.conradwood.net/h2gproxy/proxies/none"
	"golang.conradwood.net/h2gproxy/shared"
	"google.golang.org/grpc"
)

// static variables for flag parser
var (
	config_applied    = false
	config_file_names = []string{
		"h2gproxy.yaml",
		"/etc/h2gproxy/h2gproxy.yaml",
		"configs/testing.yaml",
	}
	last_parsed_config_file *pb.ConfigFile
	configctr               int
	cfgfile_lastread        time.Time
	printHeaders            = flag.Bool("print_headers", false, "if true print all headers sent and received")
	run_probes              = flag.Bool("run_probes_and_exit", false, "start server, run probes and exit (with exit code). useful for quick tests or in CI")
	activate_probe_backend  = flag.Bool("activate_probe_backend", false, "if true, the server with automatically register prober endpoints (and expose them via http to the world and locally via grpc")
	debug                   = flag.Bool("debug", false, "If true, the server will output more verbose logging")
	testcfg                 = flag.Bool("testcfg", false, "If true, the server will read the config file and exit immediately thereafter with an exitcode 0 or 10 indicating wether or not config file is valid")
	port                    = flag.Int("port", 10052, "The server port")
	cfgfile                 = flag.String("config_file", "", "Initial and optional configfile to read on startup")
	maxInFlights            = flag.Int("max_in_flights", 1000, "Maximum inflight connections for one endpoint")
	configs                 = make(map[string]*Config)
	curcfg                  *Config
	DefaultHost             = flag.String("default_host", "www.conradwood.net", "default host where to get icons from and where to go in cases of bad errors")
	AuthServer              apb.AuthenticationServiceClient
	usageStatsClient        us.UsageStatsServiceClient
	start_group             = &sync.WaitGroup{}
)

type Config struct {
	id             string
	tcpforwarders  []*TCPForwarder
	httpforwarders []*HTTPForwarder
}

// callback from the compound initialisation
func st(server *grpc.Server) error {
	s := new(H2gproxyServer)
	// Register the handler object
	pb.RegisterH2GProxyServiceServer(server, s)
	return nil
}
func Start() {
	main()
}
func main() {
	flag.Parse()
	// oddly does not apply actions if doing so
	server.SetHealth(common.Health_STARTING)
	fmt.Printf("Starting h2gproxy server...\n")
	start_group.Add(3) // waiting for certificates and config and serverstartup callback
	go wait_for_start()
	var err error
	if !*testcfg {
		authconn := client.Connect("auth.AuthenticationService")
		AuthServer = apb.NewAuthenticationServiceClient(authconn)
	}
	// read from config on startup
	fname := *cfgfile
	if fname == "" {
		for _, df := range config_file_names {
			fn, err := utils.FindFile(df)
			if err == nil {
				fname = fn
				break
			}
		}
		if fname == "" {
			fmt.Printf("Error: No config file found or specified\n")
			os.Exit(10)
		}
	}

	ctx := context.Background()
	lb := H2gproxyServer{}
	last_parsed_config_file, err = shared.Submit(ctx, &lb, fname, getDefaultHttpDef())
	cfgfile_lastread = time.Now()

	if !*testcfg {
		go setupFileWatcher(fname)
	}
	if err != nil {
		fmt.Printf("Failed to read initial config %s: %s\n", fname, err)
		os.Exit(10)
	}
	fmt.Printf("Configfile: %s\n", fname)
	if *testcfg {
		os.Exit(0)
	}
	err = proxynone.Start()
	utils.Bail("failed to start proxy [none] server", err)
	err = StartHTTPServer()
	if err != nil {
		fmt.Printf("Failed to start http server: %s\n", utils.ErrorString(err))
		os.Exit(10)
	}
	err = StartHTTPSServer()
	if err != nil {
		fmt.Printf("Failed to start https server: %s\n", utils.ErrorString(err))
		// continuing anyways (https is considered optional)
	}
	startAuthCache()
	if *activate_probe_backend || *run_probes {
		err := probe.StartHTTPBackend()
		if err != nil {
			fmt.Printf("failed to start prober backend (%s) - continuing anyways\n", err)
		}
	}
	if *run_probes {
		probe.Start()
		p := &probe.Probe{
			Host:           fmt.Sprintf("localhost:%d", portsFromString(*httpsport)[0]),
			UserToken:      os.Getenv("YACLOUD_USERTOKEN"),
			ProberEmail:    os.Getenv("YACLOUD_EMAIL"),
			ProberPassword: os.Getenv("YACLOUD_PASSWORD"),
		}
		go func() {
			time.Sleep(1 * time.Second)
			p.AllTestsAndExit()
		}()
	}
	sd := server.NewServerDef()
	sd.SetOnStartupCallback(startup)
	sd.SetPort(*port)
	sd.SetRegister(st)
	err = server.ServerStartup(sd)
	if err != nil {
		fmt.Printf("failed to start server: %s\n", err)
	}
	fmt.Printf("Done\n")
	return
}
func startup() {
	server.SetHealth(common.Health_STARTING)
	fmt.Printf("h2gproxy gRPC started...\n")
	start_group.Done()
}
func wait_for_start() {
	fmt.Printf("Waiting for h2gproxy server completion...\n")
	start_group.Wait()
	fmt.Printf("Setting server to healthy...\n")
	server.SetHealth(common.Health_READY)

}

/**********************************
* apply a new config here:
***********************************/
func apply(cfg *Config) error {
	// for http, we don't re-apply the port, only the routes
	// (so the http listen port CANNOT BE DYNAMICALLY updated)

	// shutdown all tcp listeners before starting them up again
	if curcfg != nil {
		//shutdown existing ones
		for _, tf := range curcfg.tcpforwarders {
			err := tf.Stop()
			if err != nil {
				return err
			}
		}
	}
	for _, tf := range cfg.tcpforwarders {
		tf.Forward()
	}

	// deal with special target "weblogin":
	wl := false
	for _, hf := range cfg.httpforwarders {
		wls := ""
		if hf.def.URLPath == "weblogin" {
			wls = "weblogin "
			wl = true
		}
		fmt.Printf("%sRoute: %v\n", wls, hf.def)
	}
	if !wl {
		fmt.Printf("Added weblogin route explicitly\n")
		// explicitly add /weblogin/
		hf := &HTTPForwarder{isAbsolute: true,
			def: &pb.AddConfigHTTPRequest{
				URLPath:       "/weblogin/",
				TargetService: WEBLOGIN,
				ConfigName:    "weblogin",
				MaxInFlights:  25,
				MaxPerSec:     20,
				ApiType:       "weblogin",
			}}
		cfg.httpforwarders = append(cfg.httpforwarders, hf)
	}

	// and add "acme"
	hf := &HTTPForwarder{isAbsolute: true,
		def: &pb.AddConfigHTTPRequest{
			URLPath:       "/.well-known/acme-challenge",
			TargetService: ACMESERVICE,
			ConfigName:    "acme",
			MaxInFlights:  5,
			MaxPerSec:     10,
			ApiType:       "html",
			NeedAuth:      false,
		}}
	cfg.httpforwarders = append(cfg.httpforwarders, hf)

	if *activate_probe_backend || *run_probes {
		for _, ach := range probe.HTTPRoutes() {
			cfg.httpforwarders = append(cfg.httpforwarders, &HTTPForwarder{def: ach})
		}
	}

	err := SetHTTPRoutes(cfg.httpforwarders)
	curcfg = cfg
	if err != nil {
		fmt.Printf("Failed to apply Config: %s\n", err)
	} else {
		fmt.Printf("Config applied.\n")
		if !config_applied {
			config_applied = true
			start_group.Done()
		}
	}
	return nil
}

/**********************************
* implementing the functions here:
***********************************/
type H2gproxyServer struct {
}

func (*H2gproxyServer) CreateConfig(c context.Context, cr *pb.CreateConfigRequest) (*pb.CreateConfigResponse, error) {
	configctr++
	ids := fmt.Sprintf("my config id is now %d", configctr)
	res := pb.CreateConfigResponse{ConfigID: ids}
	configs[ids] = &Config{}
	return &res, nil
}
func (*H2gproxyServer) ApplyConfig(c context.Context, cr *pb.ApplyConfigRequest) (*pb.ApplyConfigResponse, error) {
	if cr.ConfigID == "" {
		return nil, errors.New("Missing config id in AddConfigTCP Request")
	}
	cfg := configs[cr.ConfigID]
	if cfg == nil {
		return nil, errors.New(fmt.Sprintf("No such config: %s\n", cr.ConfigID))
	}
	err := apply(cfg)
	if err == nil {
		acr := pb.ApplyConfigResponse{Applied: true}
		return &acr, nil
	}
	return nil, err
}
func (*H2gproxyServer) AddConfigTCP(c context.Context, cr *pb.AddConfigTCPRequest) (*pb.AddConfigResponse, error) {
	if cr.ConfigID == "" {
		return nil, errors.New("Missing config id in AddConfigTCP Request")
	}
	if cr.SourcePort == 0 {
		return nil, errors.New("Missing port number in tcp forwarding definition")
	}
	if cr.TargetServicePath == "" {
		return nil, errors.New(fmt.Sprintf("Missing target in tcp forwarding definition for port %d", cr.SourcePort))
	}
	cfg := configs[cr.ConfigID]
	if cfg == nil {
		return nil, errors.New(fmt.Sprintf("No such config: %s\n", cr.ConfigID))
	}
	tf := TCPForwarder{Port: int(cr.SourcePort),
		Path:   cr.TargetServicePath,
		config: cr,
	}
	cfg.tcpforwarders = append(cfg.tcpforwarders, &tf)
	return &pb.AddConfigResponse{}, nil
}

func (*H2gproxyServer) AddConfigHTTP(c context.Context, cr *pb.AddConfigHTTPRequest) (*pb.AddConfigResponse, error) {
	if cr.URLPath == "" {
		return nil, errors.New("URLPath required in AddConfigHTTP() call")
	}
	apitype := shared.ApiType(cr)
	if len(cr.RedirectRewrites) == 0 {
		if apitype == 5 && cr.URLHostname == "" {
			return nil, fmt.Errorf("[%s] does not set urlhost (%s) and apitype is proxy (%s)", cr.ConfigName, cr.URLHostname, cr.URLPath)
		}
		if apitype != 0 && cr.TargetHost != "" {
			return nil, fmt.Errorf("[%s] do not set targethost (%s) and apitype != 0 (%s)", cr.ConfigName, cr.TargetHost, cr.URLPath)
		}
		if (cr.TargetHost == "") && (cr.TargetService == "") {
			return nil, fmt.Errorf("[%s] Either TargetHost or TargetService required in AddConfigHTTP() (api=%v) call", cr.ConfigName, apitype)
		}
		if (cr.TargetHost != "") && (cr.TargetPort == 0) {
			return nil, errors.New(fmt.Sprintf("If TargetHost is specified, TargetPort is mandatory in AddConfigHTTP() call (%s)", cr.TargetHost))
		}
		if (cr.Groups != nil) && (len(cr.Groups) != 0) && (cr.NeedAuth == false) {
			return nil, fmt.Errorf("Groups specified, but needauth=false in %s", cr.URLPath)
		}
		if apitype > 999 {
			return nil, errors.New(fmt.Sprintf("Invalid api type (configname=%s)", cr.ConfigName))
		}
	}
	if cr.ConfigID == "" {
		return nil, errors.New("entry MUST have a configid")
	}
	cfg := configs[cr.ConfigID]
	if cfg == nil {
		return nil, errors.New(fmt.Sprintf("No such config: %s\n", cr.ConfigID))
	}
	for _, hf := range cfg.httpforwarders {
		// we don't check groups here because it gets way too complicated
		// the usecase seems dubious too. (route the same url to different backends based on user?)
		// (We can still handle versions as long as it's the same backend)
		if (hf.def.URLPath == cr.URLPath) && (hf.def.URLHostname == cr.URLHostname) && (hf.def.ProtocolRequired == cr.ProtocolRequired) && (hf.def.RFC1918Only == cr.RFC1918Only) {
			return nil, errors.New(fmt.Sprintf("URLPath %s defined twice on host \"%s\" with protocol \"%s\"\n", cr.URLPath, cr.URLHostname, cr.ProtocolRequired))
		}
	}
	// make sure people don't use this until implemented!
	if len(cr.Users) > 0 {
		return nil, errors.New(fmt.Sprintf("HTTP forwarding matcher not implemented %v!", cr))
	}
	if cr.TargetHost != "" {
		fmt.Printf("Forwarding HTTP requests %s to %s:%d\n", cr.URLPath, cr.TargetHost, cr.TargetPort)
	} else {
		fmt.Printf("Forwarding HTTP requests %s to %s[/%s]\n", cr.URLPath, cr.TargetService, cr.PathPrefix)
	}
	hf := HTTPForwarder{}
	hf.def = cr
	cfg.httpforwarders = append(cfg.httpforwarders, &hf)
	return &pb.AddConfigResponse{}, nil
}

// create a ticker and regularly stat the configfile
// to see if modification date changed
func setupFileWatcher(filename string) {
	c := time.Tick(5 * time.Second)
	for now := range c {
		info, err := os.Stat(filename)
		if err != nil {
			fmt.Printf("Failed to stat config file %s: %s\n", filename, err)
			continue
		}
		if info.ModTime().After(cfgfile_lastread) {
			ctx := context.Background()
			lb := H2gproxyServer{}
			cfgfile, err := shared.Submit(ctx, &lb, filename, getDefaultHttpDef())
			if err != nil {
				fmt.Printf("Failed to read config %s: %s\n", filename, err)
				continue
			}
			cfgfile_lastread = now
			last_parsed_config_file = cfgfile
		}
		if err != nil {
			fmt.Printf("Error reading certs: %s\n", err)
		}
	}
}

func (*H2gproxyServer) GetConfig(ctx context.Context, req *common.Void) (*pb.Config, error) {
	res := &pb.Config{}
	cfg := curcfg
	for _, c := range cfg.httpforwarders {
		res.Config = append(res.Config, c.def)
	}
	return res, nil
}

func getDefaultHttpDef() shared.Httpdef {
	res := shared.Httpdef{}
	res.MaxInFlights = int32(*maxInFlights)
	return res
}

func getGlobalConfigSection() *pb.GlobalConfig {
	return last_parsed_config_file.GlobalConfig
}
