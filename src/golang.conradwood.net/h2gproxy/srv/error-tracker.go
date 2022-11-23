package srv

import (
	rpb "golang.conradwood.net/apis/registry"
	"sync"
)

var (
	targets []*Target
	lock    sync.Mutex
)

type Target struct {
	host     string
	port     int
	errorctr int
}

func (t *Target) isAdr(host string, port int) bool {
	if (t.host != host) || (t.port != port) {
		return false
	}
	return true

}

func (t *Target) ServiceAddress() *rpb.ServiceAddress {
	sa := rpb.ServiceAddress{Host: t.host, Port: int32(t.port)}
	return &sa
}

func findTarget(host string, port int) *Target {
	lock.Lock()
	defer lock.Unlock()
	for _, t := range targets {
		if t.isAdr(host, port) {
			return t
		}
	}
	t := Target{host: host, port: port, errorctr: 0}
	targets = append(targets, &t)
	return &t
}

func FilterByLeastErrors(locations *rpb.ServiceLocation) *rpb.ServiceAddress {
	var ct *Target
	for _, sa := range locations.Address {
		t := findTarget(sa.Host, int(sa.Port))
		if (ct == nil) || (ct.errorctr > t.errorctr) {
			ct = t
		}
	}
	return ct.ServiceAddress()
}
