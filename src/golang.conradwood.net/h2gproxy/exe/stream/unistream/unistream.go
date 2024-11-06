/*
grpc backend receives a unary request and responds with a stream
*/
package unistream

import "golang.conradwood.net/h2gproxy/stream"

/*****************************
* streaming download proxy
*
* apitype: download
* Backend: rpc StreamHTTP(StreamRequest) returns (stream StreamDataResponse);
* StreamDataResponse includes a "StreamRespose" which must be sent before data
*****************************/

func Stream(stream.RequestDetails) {
}
