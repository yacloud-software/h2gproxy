// client create: H2GProxyServiceClient
/*
  Created by /home/cnw/devel/go/yatools/src/golang.yacloud.eu/yatools/protoc-gen-cnw/protoc-gen-cnw.go
*/

/* geninfo:
   filename  : protos/golang.conradwood.net/apis/h2gproxy/h2gproxy.proto
   gopackage : golang.conradwood.net/apis/h2gproxy
   importname: ai_2
   clientfunc: GetH2GProxyService
   serverfunc: NewH2GProxyService
   lookupfunc: H2GProxyServiceLookupID
   varname   : client_H2GProxyServiceClient_2
   clientname: H2GProxyServiceClient
   servername: H2GProxyServiceServer
   gsvcname  : h2gproxy.H2GProxyService
   lockname  : lock_H2GProxyServiceClient_2
   activename: active_H2GProxyServiceClient_2
*/

package h2gproxy

import (
   "sync"
   "golang.conradwood.net/go-easyops/client"
)
var (
  lock_H2GProxyServiceClient_2 sync.Mutex
  client_H2GProxyServiceClient_2 H2GProxyServiceClient
)

func GetH2GProxyClient() H2GProxyServiceClient { 
    if client_H2GProxyServiceClient_2 != nil {
        return client_H2GProxyServiceClient_2
    }

    lock_H2GProxyServiceClient_2.Lock() 
    if client_H2GProxyServiceClient_2 != nil {
       lock_H2GProxyServiceClient_2.Unlock()
       return client_H2GProxyServiceClient_2
    }

    client_H2GProxyServiceClient_2 = NewH2GProxyServiceClient(client.Connect(H2GProxyServiceLookupID()))
    lock_H2GProxyServiceClient_2.Unlock()
    return client_H2GProxyServiceClient_2
}

func GetH2GProxyServiceClient() H2GProxyServiceClient { 
    if client_H2GProxyServiceClient_2 != nil {
        return client_H2GProxyServiceClient_2
    }

    lock_H2GProxyServiceClient_2.Lock() 
    if client_H2GProxyServiceClient_2 != nil {
       lock_H2GProxyServiceClient_2.Unlock()
       return client_H2GProxyServiceClient_2
    }

    client_H2GProxyServiceClient_2 = NewH2GProxyServiceClient(client.Connect(H2GProxyServiceLookupID()))
    lock_H2GProxyServiceClient_2.Unlock()
    return client_H2GProxyServiceClient_2
}

func H2GProxyServiceLookupID() string { return "h2gproxy.H2GProxyService" } // returns the ID suitable for lookup in the registry. treat as opaque, subject to change.

func init() {
   client.RegisterDependency("h2gproxy.H2GProxyService")
   AddService("h2gproxy.H2GProxyService")
}
