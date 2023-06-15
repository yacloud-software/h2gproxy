// client create: DownloadStreamerClient
/*
  Created by /srv/home/cnw/devel/go/go-tools/src/golang.conradwood.net/gotools/protoc-gen-cnw/protoc-gen-cnw.go
*/

/* geninfo:
   filename  : protos/golang.conradwood.net/apis/h2gproxy/h2gproxy.proto
   gopackage : golang.conradwood.net/apis/h2gproxy
   importname: ai_0
   clientfunc: GetDownloadStreamer
   serverfunc: NewDownloadStreamer
   lookupfunc: DownloadStreamerLookupID
   varname   : client_DownloadStreamerClient_0
   clientname: DownloadStreamerClient
   servername: DownloadStreamerServer
   gscvname  : h2gproxy.DownloadStreamer
   lockname  : lock_DownloadStreamerClient_0
   activename: active_DownloadStreamerClient_0
*/

package h2gproxy

import (
   "sync"
   "golang.conradwood.net/go-easyops/client"
)
var (
  lock_DownloadStreamerClient_0 sync.Mutex
  client_DownloadStreamerClient_0 DownloadStreamerClient
)

func GetDownloadStreamerClient() DownloadStreamerClient { 
    if client_DownloadStreamerClient_0 != nil {
        return client_DownloadStreamerClient_0
    }

    lock_DownloadStreamerClient_0.Lock() 
    if client_DownloadStreamerClient_0 != nil {
       lock_DownloadStreamerClient_0.Unlock()
       return client_DownloadStreamerClient_0
    }

    client_DownloadStreamerClient_0 = NewDownloadStreamerClient(client.Connect(DownloadStreamerLookupID()))
    lock_DownloadStreamerClient_0.Unlock()
    return client_DownloadStreamerClient_0
}

func DownloadStreamerLookupID() string { return "h2gproxy.DownloadStreamer" } // returns the ID suitable for lookup in the registry. treat as opaque, subject to change.
