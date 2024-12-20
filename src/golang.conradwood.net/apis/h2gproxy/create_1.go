// client create: WebsocketProxyClient
/*
  Created by /home/cnw/devel/go/yatools/src/golang.yacloud.eu/yatools/protoc-gen-cnw/protoc-gen-cnw.go
*/

/* geninfo:
   rendererv : 2
   filename  : golang.conradwood.net/apis/h2gproxy/h2gproxy.proto
   gopackage : golang.conradwood.net/apis/h2gproxy
   importname: ai_0
   clientfunc: GetWebsocketProxy
   serverfunc: NewWebsocketProxy
   lookupfunc: WebsocketProxyLookupID
   varname   : client_WebsocketProxyClient_0
   clientname: WebsocketProxyClient
   servername: WebsocketProxyServer
   gsvcname  : h2gproxy.WebsocketProxy
   lockname  : lock_WebsocketProxyClient_0
   activename: active_WebsocketProxyClient_0
*/

package h2gproxy

import (
   "sync"
   "golang.conradwood.net/go-easyops/client"
)
var (
  lock_WebsocketProxyClient_0 sync.Mutex
  client_WebsocketProxyClient_0 WebsocketProxyClient
)

func GetWebsocketProxyClient() WebsocketProxyClient { 
    if client_WebsocketProxyClient_0 != nil {
        return client_WebsocketProxyClient_0
    }

    lock_WebsocketProxyClient_0.Lock() 
    if client_WebsocketProxyClient_0 != nil {
       lock_WebsocketProxyClient_0.Unlock()
       return client_WebsocketProxyClient_0
    }

    client_WebsocketProxyClient_0 = NewWebsocketProxyClient(client.Connect(WebsocketProxyLookupID()))
    lock_WebsocketProxyClient_0.Unlock()
    return client_WebsocketProxyClient_0
}

func WebsocketProxyLookupID() string { return "h2gproxy.WebsocketProxy" } // returns the ID suitable for lookup in the registry. treat as opaque, subject to change.

func init() {
   client.RegisterDependency("h2gproxy.WebsocketProxy")
   AddService("h2gproxy.WebsocketProxy")
}
