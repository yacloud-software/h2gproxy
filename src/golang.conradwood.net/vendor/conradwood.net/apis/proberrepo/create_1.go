// client create: ProberRepoServiceClient
/* geninfo:
   filename  : conradwood.net/apis/proberrepo/proberrepo.proto
   gopackage : conradwood.net/apis/proberrepo
   importname: ai_0
   varname   : client_ProberRepoServiceClient_0
   clientname: ProberRepoServiceClient
   servername: ProberRepoServiceServer
   gscvname  : proberrepo.ProberRepoService
   lockname  : lock_ProberRepoServiceClient_0
   activename: active_ProberRepoServiceClient_0
*/

package proberrepo

import (
   "sync"
   "golang.conradwood.net/go-easyops/client"
)
var (
  lock_ProberRepoServiceClient_0 sync.Mutex
  client_ProberRepoServiceClient_0 ProberRepoServiceClient
)

func GetProberRepoClient() ProberRepoServiceClient { 
    if client_ProberRepoServiceClient_0 != nil {
        return client_ProberRepoServiceClient_0
    }

    lock_ProberRepoServiceClient_0.Lock() 
    if client_ProberRepoServiceClient_0 != nil {
       lock_ProberRepoServiceClient_0.Unlock()
       return client_ProberRepoServiceClient_0
    }

    client_ProberRepoServiceClient_0 = NewProberRepoServiceClient(client.Connect("proberrepo.ProberRepoService"))
    lock_ProberRepoServiceClient_0.Unlock()
    return client_ProberRepoServiceClient_0
}

func GetProberRepoServiceClient() ProberRepoServiceClient { 
    if client_ProberRepoServiceClient_0 != nil {
        return client_ProberRepoServiceClient_0
    }

    lock_ProberRepoServiceClient_0.Lock() 
    if client_ProberRepoServiceClient_0 != nil {
       lock_ProberRepoServiceClient_0.Unlock()
       return client_ProberRepoServiceClient_0
    }

    client_ProberRepoServiceClient_0 = NewProberRepoServiceClient(client.Connect("proberrepo.ProberRepoService"))
    lock_ProberRepoServiceClient_0.Unlock()
    return client_ProberRepoServiceClient_0
}

