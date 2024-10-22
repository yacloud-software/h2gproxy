// client create: DownloadStreamerClient
/*
  Created by /home/cnw/devel/go/yatools/src/golang.yacloud.eu/yatools/protoc-gen-cnw/protoc-gen-cnw.go
*/

/* geninfo:
   filename  : golang.conradwood.net/apis/h2gproxy/h2gproxy.proto
   gopackage : golang.conradwood.net/apis/h2gproxy
   importname: ai_2
   clientfunc: GetDownloadStreamer
   serverfunc: NewDownloadStreamer
   lookupfunc: DownloadStreamerLookupID
   varname   : client_DownloadStreamerClient_2
   clientname: DownloadStreamerClient
   servername: DownloadStreamerServer
   gsvcname  : h2gproxy.DownloadStreamer
   lockname  : lock_DownloadStreamerClient_2
   activename: active_DownloadStreamerClient_2
*/

package h2gproxy

import (
   "sync"
   "golang.conradwood.net/go-easyops/client"
)
var (
  lock_DownloadStreamerClient_2 sync.Mutex
  client_DownloadStreamerClient_2 DownloadStreamerClient
)

func GetDownloadStreamerClient() DownloadStreamerClient { 
    if client_DownloadStreamerClient_2 != nil {
        return client_DownloadStreamerClient_2
    }

    lock_DownloadStreamerClient_2.Lock() 
    if client_DownloadStreamerClient_2 != nil {
       lock_DownloadStreamerClient_2.Unlock()
       return client_DownloadStreamerClient_2
    }

    client_DownloadStreamerClient_2 = NewDownloadStreamerClient(client.Connect(DownloadStreamerLookupID()))
    lock_DownloadStreamerClient_2.Unlock()
    return client_DownloadStreamerClient_2
}

func DownloadStreamerLookupID() string { return "h2gproxy.DownloadStreamer" } // returns the ID suitable for lookup in the registry. treat as opaque, subject to change.

func init() {
   client.RegisterDependency("h2gproxy.DownloadStreamer")
   AddService("h2gproxy.DownloadStreamer")
}
