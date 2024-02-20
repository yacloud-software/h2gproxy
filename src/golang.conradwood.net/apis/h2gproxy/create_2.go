// client create: BiDirectionalStreamerClient
/*
  Created by /home/cnw/devel/go/yatools/src/golang.yacloud.eu/yatools/protoc-gen-cnw/protoc-gen-cnw.go
*/

/* geninfo:
   filename  : protos/golang.conradwood.net/apis/h2gproxy/h2gproxy.proto
   gopackage : golang.conradwood.net/apis/h2gproxy
   importname: ai_1
   clientfunc: GetBiDirectionalStreamer
   serverfunc: NewBiDirectionalStreamer
   lookupfunc: BiDirectionalStreamerLookupID
   varname   : client_BiDirectionalStreamerClient_1
   clientname: BiDirectionalStreamerClient
   servername: BiDirectionalStreamerServer
   gsvcname  : h2gproxy.BiDirectionalStreamer
   lockname  : lock_BiDirectionalStreamerClient_1
   activename: active_BiDirectionalStreamerClient_1
*/

package h2gproxy

import (
   "sync"
   "golang.conradwood.net/go-easyops/client"
)
var (
  lock_BiDirectionalStreamerClient_1 sync.Mutex
  client_BiDirectionalStreamerClient_1 BiDirectionalStreamerClient
)

func GetBiDirectionalStreamerClient() BiDirectionalStreamerClient { 
    if client_BiDirectionalStreamerClient_1 != nil {
        return client_BiDirectionalStreamerClient_1
    }

    lock_BiDirectionalStreamerClient_1.Lock() 
    if client_BiDirectionalStreamerClient_1 != nil {
       lock_BiDirectionalStreamerClient_1.Unlock()
       return client_BiDirectionalStreamerClient_1
    }

    client_BiDirectionalStreamerClient_1 = NewBiDirectionalStreamerClient(client.Connect(BiDirectionalStreamerLookupID()))
    lock_BiDirectionalStreamerClient_1.Unlock()
    return client_BiDirectionalStreamerClient_1
}

func BiDirectionalStreamerLookupID() string { return "h2gproxy.BiDirectionalStreamer" } // returns the ID suitable for lookup in the registry. treat as opaque, subject to change.

func init() {
   client.RegisterDependency("h2gproxy.BiDirectionalStreamer")
   AddService("h2gproxy.BiDirectionalStreamer")
}
