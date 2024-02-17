// client create: DownloadStreamerClient
/*
  Created by /home/cnw/devel/go/yatools/src/golang.yacloud.eu/yatools/protoc-gen-cnw/protoc-gen-cnw.go
*/

/* geninfo:
   filename  : protos/golang.conradwood.net/apis/h2gproxy/h2gproxy.proto
   gopackage : golang.conradwood.net/apis/h2gproxy
   importname: ai_1
   clientfunc: GetDownloadStreamer
   serverfunc: NewDownloadStreamer
   lookupfunc: DownloadStreamerLookupID
   varname   : client_DownloadStreamerClient_1
   clientname: DownloadStreamerClient
   servername: DownloadStreamerServer
   gsvcname  : h2gproxy.DownloadStreamer
   lockname  : lock_DownloadStreamerClient_1
   activename: active_DownloadStreamerClient_1
*/

package h2gproxy

import (
   "sync"
   "golang.conradwood.net/go-easyops/client"
)
var (
  lock_DownloadStreamerClient_1 sync.Mutex
  client_DownloadStreamerClient_1 DownloadStreamerClient
)

func GetDownloadStreamerClient() DownloadStreamerClient { 
    if client_DownloadStreamerClient_1 != nil {
        return client_DownloadStreamerClient_1
    }

    lock_DownloadStreamerClient_1.Lock() 
    if client_DownloadStreamerClient_1 != nil {
       lock_DownloadStreamerClient_1.Unlock()
       return client_DownloadStreamerClient_1
    }

    client_DownloadStreamerClient_1 = NewDownloadStreamerClient(client.Connect(DownloadStreamerLookupID()))
    lock_DownloadStreamerClient_1.Unlock()
    return client_DownloadStreamerClient_1
}

func DownloadStreamerLookupID() string { return "h2gproxy.DownloadStreamer" } // returns the ID suitable for lookup in the registry. treat as opaque, subject to change.

func init() {
   client.RegisterDependency("h2gproxy.DownloadStreamer")
   AddService("h2gproxy.DownloadStreamer")
}
