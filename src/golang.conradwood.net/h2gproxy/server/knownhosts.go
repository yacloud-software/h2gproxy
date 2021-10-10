package main

import (
	"context"
	"golang.conradwood.net/apis/common"
	pb "golang.conradwood.net/apis/h2gproxy"
	"sort"
	"strings"
	"sync"
)

const (
	MAX_SIZE_OF_HOSTS_MAP = 200
)

var (
	hosts    = make(map[string]*pb.HostListEntry)
	hostlock sync.Mutex
)

func (*H2gproxyServer) GetKnownHosts(ctx context.Context, req *common.Void) (*pb.HostList, error) {
	res := &pb.HostList{}
	// lock and quickly make a copy
	hostlock.Lock()
	for _, v := range hosts {
		res.Hosts = append(res.Hosts, v)
	}
	hostlock.Unlock()
	// now do slow stuff
	for _, h := range res.Hosts {
		h.GotCertificate = HaveCert(h.Hostname)
	}
	sort.Slice(res.Hosts, func(i, j int) bool {
		return res.Hosts[i].Hostname < res.Hosts[j].Hostname
	})
	return res, nil
}

// add a host to our list
func NoteHost(hostname string, tls bool) {

	hname := strings.ToLower(hostname)
	sx := strings.Split(hname, ":")
	if len(sx) > 1 {
		hname = sx[0]
	}
	hostlock.Lock()
	if len(hosts) > MAX_SIZE_OF_HOSTS_MAP { // some safety here
		hostlock.Unlock()
		return
	}
	hle := hosts[hname]
	if hle == nil {
		hle = &pb.HostListEntry{Hostname: hname}
		hosts[hname] = hle
	}
	hostlock.Unlock()
	if tls {
		hle.ServedHTTPS = true
	} else {
		hle.ServedHTTP = true
	}

}
