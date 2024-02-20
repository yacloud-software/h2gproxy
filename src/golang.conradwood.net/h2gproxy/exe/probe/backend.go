package probe

import (
	"context"
	"crypto/sha256"
	"fmt"
	pb "golang.conradwood.net/apis/h2gproxy"
	"golang.conradwood.net/go-easyops/errors"
	"golang.conradwood.net/go-easyops/utils"
	"golang.conradwood.net/h2gproxy/shared"
	"strconv"
	"strings"
)

const (
	printables = "abcdefg"
)

// create routes for our prober
func HTTPRoutes() []*pb.AddConfigHTTPRequest {
	var res []*pb.AddConfigHTTPRequest
	res = append(res, stdcfg("html", 2, false))
	res = append(res, stdcfg("html", 2, true))
	res = append(res, stdcfg("download", 4, false))
	res = append(res, stdcfg("download", 4, true))
	res = append(res, stdcfg("json", 1, false))
	res = append(res, stdcfg("json", 1, true))
	res = append(res, stdcfg("none", 0, false))
	res = append(res, stdcfg("none", 0, true))
	return res
}
func stdcfg(suffix string, apitype uint32, auth bool) *pb.AddConfigHTTPRequest {
	bp := strings.Trim(BASE_PATH, "/")
	as := "noauth"
	if auth {
		as = "auth"
	}
	ts := "h2gproxy.H2GProxyService"
	if apitype == 0 {
		ts = "h2gproxy.Prober"
	}
	up := "/" + bp + "/" + as + "/" + suffix
	res := &pb.AddConfigHTTPRequest{
		URLPath:                      up,
		PathPrefix:                   up, //make sure we pass 'up' to the backend (otherwise h2gproxy strips it)
		TargetService:                ts,
		ConfigName:                   "probers",
		MaxInFlights:                 5,
		MaxPerSec:                    10,
		ApiType:                      shared.ApiTypeByNum(apitype),
		NeedAuth:                     auth,
		AllowAuthorizationFromClient: false, // otherwise the backend cannot trigger form login
	}
	fmt.Printf("Adding url %s as prober, apitype %s, needauth=%v\n", res.URLPath, res.ApiType, res.NeedAuth)
	return res
}

/***************************************************************************************
one the routes are added as above, the h2gproxy server will route the requests to itself
via grpc (thus mimicking the flow).
it forwards the requests to the probe into these functions
*/
//html
func ServeHTML(ctx context.Context, req *pb.ServeRequest) (*pb.ServeResponse, error) {
	fmt.Printf("[prober-backend] ServeHTML() %s\n", req.Path)
	if wantAuth(req) {
		fmt.Printf("[prober-backend] caller requested to return unauthenticated(), doing so now\n")
		return nil, errors.Unauthenticated(ctx, "caller asked for authentication)")
	}
	user := ""
	for _, p := range req.Parameters {
		if p.Name == "echo" {
			user = p.Value
		}
	}
	b := []byte(PROBE_IDENTIFIER + user)
	as := utils.RandomString(utils.RandomInt(5000))
	b = append(b, []byte(as)...)
	res := &pb.ServeResponse{
		Body:     b,
		MimeType: "text/html",
	}
	return res, nil
}

/*
	.../data -> streams some data
	.../checksum -> get checksum over data

?seed=foobar slighly changes data
?size=100000 different data size
(checksum will match if seed&size are the same as for data)
*/
func StreamHTTP(req *pb.StreamRequest, srv pb.H2GProxyService_StreamHTTPServer) error {
	var err error
	fmt.Printf("[prober-backend] StreamHTTP() %s\n", req.Path)
	if wantAuth(req) {
		return errors.Unauthenticated(srv.Context(), "caller asked for authentication")
	}
	blocksize := 8192
	seed := "nothing"
	datasize := uint64(12 * 1024 * 1024)
	for _, p := range req.Parameters {
		if p.Name == "seed" {
			seed = p.Value
		}
		if p.Name == "size" {
			datasize, err = strconv.ParseUint(p.Value, 10, 64)
			if err != nil {
				return err
			}
		}
	}
	var data []byte
	if strings.HasSuffix(req.Path, "data") {
		data = makeBuf(seed, datasize)
	} else if strings.HasSuffix(req.Path, "checksum") {
		buf := makeBuf(seed, datasize)
		c := CheckSum(buf)
		data = []byte(fmt.Sprintf("DATA CHECKSUM %s", c))
		data = append(data, []byte("\n"+PROBE_IDENTIFIER)...)
	} else {
		return errors.NotFound(srv.Context(), "[proberbackend] no such path: %s", req.Path)
	}
	size := len(data)
	err = srv.Send(&pb.StreamDataResponse{Response: &pb.StreamResponse{
		Filename: "foofilename",
		Size:     uint64(size),
		MimeType: "application/octet-stream",
	}})
	if err != nil {
		return err
	}
	sent := 0
	for {
		rs := blocksize
		if sent+rs > size {
			rs = size - sent
		}
		buf := data[sent : sent+rs]
		err = srv.Send(&pb.StreamDataResponse{Data: buf})
		if err != nil {
			return err
		}
		sent = sent + rs
		if sent >= size {
			break
		}
	}
	return nil
}

// json
func Serve(ctx context.Context, req *pb.ServeRequest) (*pb.ServeResponse, error) {
	fmt.Printf("[prober-backend] Serve() %s\n", req.Path)
	if wantAuth(req) {
		return nil, errors.Unauthenticated(ctx, "caller asked for authentication")
	}
	return nil, nil

}

type WithHeaders interface {
	GetHeaders() []*pb.Header
	GetParameters() []*pb.Parameter
}

func printHeaders(wh WithHeaders) {
	for _, h := range wh.GetHeaders() {
		if len(h.Values) == 0 {
			continue
		}
		v := h.Values[0]
		fmt.Printf("Header %s=%s\n", h.Name, v)
	}
}
func wantAuth(wh WithHeaders) bool {
	for _, h := range wh.GetHeaders() {
		if strings.ToLower(h.Name) == "authme" {
			if len(h.Values) == 0 {
				return false
			}
			return strings.ToLower(h.Values[0]) == "true"
		}
	}
	return false
}

func makeBuf(seed string, datasize uint64) []byte {
	res := make([]byte, datasize-uint64(len("\n"+PROBE_IDENTIFIER)))
	l := 0
	i := 0
	chars := seed + printables
	for {
		res[i] = chars[l]
		i++
		l++
		if l >= len(chars) {
			l = 0
		}
		if i >= len(res) {
			break
		}

	}
	res = append(res, []byte("\n"+PROBE_IDENTIFIER)...)
	return res
}

func CheckSum(buf []byte) string {
	cs := sha256.Sum256(buf)
	s := "SHA256:"
	for _, b := range cs {
		s = s + fmt.Sprintf("%02X", b)
	}
	return s
}
