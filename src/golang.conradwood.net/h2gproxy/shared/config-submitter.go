package shared

// parses a yaml file and submits to server

import (
	"fmt"
	pb "golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/go-easyops/utils"
	"golang.org/x/net/context"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"strings"
)

type lbps interface {
	CreateConfig(c context.Context, cr *pb.CreateConfigRequest) (*pb.CreateConfigResponse, error)
	ApplyConfig(c context.Context, cr *pb.ApplyConfigRequest) (*pb.ApplyConfigResponse, error)
	AddConfigTCP(c context.Context, cr *pb.AddConfigTCPRequest) (*pb.AddConfigResponse, error)
	AddConfigHTTP(c context.Context, cr *pb.AddConfigHTTPRequest) (*pb.AddConfigResponse, error)
}

type lbpsimpl struct {
	lb pb.H2GProxyServiceClient
}

func (l *lbpsimpl) AddConfigHTTP(c context.Context, cr *pb.AddConfigHTTPRequest) (*pb.AddConfigResponse, error) {
	return l.lb.AddConfigHTTP(c, cr)
}
func (l *lbpsimpl) AddConfigTCP(c context.Context, cr *pb.AddConfigTCPRequest) (*pb.AddConfigResponse, error) {
	return l.lb.AddConfigTCP(c, cr)
}
func (l *lbpsimpl) ApplyConfig(c context.Context, cr *pb.ApplyConfigRequest) (*pb.ApplyConfigResponse, error) {
	return l.lb.ApplyConfig(c, cr)
}
func (l *lbpsimpl) CreateConfig(c context.Context, cr *pb.CreateConfigRequest) (*pb.CreateConfigResponse, error) {
	return l.lb.CreateConfig(c, cr)
}

type ConfigFile struct {
	Tcpproxy  []*Tcpdef
	Httpproxy []*Httpdef
}
type Tcpdef struct {
	Port             int
	Target           string
	KeepAliveSeconds uint32
}

// changed made here will need to be copied
// into code below
// this corresponds to the yaml config file structure
type Httpdef struct {
	pb.AddConfigHTTPRequest `yaml:",inline"`
	Apitype                 string
}

func (hd *Httpdef) TargetString() string {
	if hd.TargetService != "" {
		if hd.PathPrefix != "" {
			return fmt.Sprintf("%s[/%s]", hd.TargetService, hd.PathPrefix)
		}
		return hd.TargetService
	}
	return fmt.Sprintf("http://%s:%d", hd.TargetHost, hd.TargetPort)
}

func SubmitClient(ctx context.Context, lb pb.H2GProxyServiceClient, fname string, def Httpdef) error {
	lbps := lbpsimpl{lb: lb}
	return Submit(ctx, &lbps, fname, def)
}
func Submit(ctx context.Context, lb lbps, fname string, def Httpdef) error {
	fmt.Printf("Config: %s\n", fname)
	fb, err := ioutil.ReadFile(fname)
	if err != nil {
		fmt.Printf("Failed to read file %s: %s\n", fname, err)
		return err
	}
	gd := ConfigFile{}
	err = yaml.UnmarshalStrict(fb, &gd)
	if err != nil {
		fmt.Printf("Failed to parse file %s: %s\n", fname, err)
		return err
	}
	ccr, err := lb.CreateConfig(ctx, &pb.CreateConfigRequest{})
	if err != nil {
		fmt.Printf("Failed to create config: %s\n", err)
		return err
	}
	configid := ccr.ConfigID
	fmt.Printf("Created config with id %s\n", configid)
	for _, tcpdef := range gd.Tcpproxy {
		fmt.Printf("Forwarding port %d to \"%s\"\n", tcpdef.Port, tcpdef.Target)

		addreq := &pb.AddConfigTCPRequest{
			ConfigID:          configid,
			SourcePort:        int32(tcpdef.Port),
			TargetServicePath: tcpdef.Target,
			KeepAliveSeconds:  tcpdef.KeepAliveSeconds,
		}

		_, err := lb.AddConfigTCP(ctx, addreq)
		if err != nil {
			return err
		}

	}
	for _, hd := range gd.Httpproxy {
		fmt.Printf("Config: Forwarding HTTP requests to %s:%s to \"%s\"\n", hd.URLHostname, hd.URLPath, hd.TargetString())
		for _, header := range hd.Header {
			fmt.Printf("   Header: %s\n", header)
		}
		for _, group := range hd.Groups {
			fmt.Printf("   Groups: %s\n", group)
		}
		if hd.ConfigName == "" {
			th := hd.TargetHost
			if th == "" {
				th = hd.TargetService
			}
			hd.ConfigName = fmt.Sprintf("%s@%s", hd.URLPath, th)
		}

		// set the default MaxInFlights if it's not been set in the config file and there's a maxInFlights default value
		if hd.MaxInFlights == 0 && def.MaxInFlights > 0 {
			hd.MaxInFlights = def.MaxInFlights
		}
		/*
			xaddreq := &pb.AddConfigHTTPRequest{
				ConfigID:                     configid,
				URLPath:                      hd.URLPath,
				URLHostname:                  hd.URLHostname,
				TargetHost:                   hd.TargetHost,
				TargetPort:                   int32(hd.TargetPort),
				TargetService:                hd.TargetService,
				TargetURL:                    hd.TargetURL,
				TargetHostname:               hd.TargetHostname,
				PathPrefix:                   hd.PathPrefix,
				Header:                       hd.Header,
				NeedAuth:                     hd.NeedAuth,
				Groups:                       hd.Groups,
				Users:                        hd.Users,
				ForwardedFor:                 hd.ForwardedFor,
				ErrorPage500:                 hd.ErrorPage500,
				SendFakeAuthorization:        hd.SendFakeAuthorization,
				ForwardedHost:                hd.ForwardedHost,
				ConfigName:                   hd.ConfigName,
				ProtocolRequired:             hd.ProtocolRequired,
				AllowAuthorizationFromClient: hd.AllowAuthorizationFromClient,
				ForceBackendAuthorization:    hd.ForceBackendAuthorization,
				MaxInFlights:                 hd.MaxInFlights,
				Api:                          hd.ApiType(),
				RewriteRedirectHost:          hd.RewriteRedirectHost,
				UserNameForFakeAuth:          hd.UserNameForFakeAuth,
				MaxPerSec:                    uint32(hd.MaxPerSec),
				RFC1918Only:                  hd.RFC1918Only,
				AcceptHTTP:                   hd.AcceptHTTP,
			}
		*/
		hd.ConfigID = configid
		hd.Api = hd.ApiType()
		addreq := &hd.AddConfigHTTPRequest
		//		fmt.Printf("AddReq: %#v\n", addreq)
		_, err := lb.AddConfigHTTP(ctx, addreq)
		if err != nil {
			fmt.Printf("Config Parser failed to submit it: %s\n", utils.ErrorString(err))
			return err
		}

	}
	_, err = lb.ApplyConfig(ctx, &pb.ApplyConfigRequest{ConfigID: configid})
	return err
}

func (h *Httpdef) ApiType() uint32 {
	s := strings.ToLower(h.Apitype)
	if s == "none" || s == "" {
		return 0
	} else if s == "json" {
		return 1
	} else if s == "html" {
		return 2
		// 3 -> weblogin
	} else if s == "download" {
		return 4
	} else if s == "proxy" {
		return 5
	}
	return 1000 // error
}
