package srv

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/golang/protobuf/proto"
	ic "golang.conradwood.net/apis/rpcinterceptor"
	"golang.conradwood.net/go-easyops/client"
	"golang.conradwood.net/go-easyops/rpc"
	"golang.conradwood.net/go-easyops/tokens"
	"google.golang.org/grpc/metadata"
)

var (
	debugctx = flag.Bool("debug_ctx", false, "debug context transformations and user metadata")
)

func createContext(f *FProxy, a *authResult, rp *ic.InterceptRPCResponse) (context.Context, error) {
	secs := f.hf.def.MaxDuration
	if secs == 0 {
		if f.hf.def.Api == 4 {
			secs = 600 // streaming is longer by default
		} else {
			secs = 10
		}
	}
	octx := tokens.ContextWithTokenAndTimeout(uint64(secs))
	return createContextWith(octx, f, a, rp)
}
func createContextWith(octx context.Context, f *FProxy, a *authResult, rp *ic.InterceptRPCResponse) (context.Context, error) {
	if octx.Err() != nil {
		// no point calling out with a failed context
		return nil, octx.Err()
	}
	ctx, cs := rpc.ContextWithCallState(octx)

	ix := f.md
	if ix == nil {
		ix = &ic.InMetadata{}
		f.md = ix
	}

	if rp != nil {
		ix.RequestID = rp.RequestID
	}
	if f.unsigneduser != nil {
		ix.UserID = f.unsigneduser.ID
	}
	ix.SignedSession = f.session
	ix.ServiceToken = tokens.GetServiceTokenParameter()
	if *debugctx {
		fmt.Printf("New IX Metadata: %#v\n", ix)
	}
	// build a new context
	data, err := proto.Marshal(ix)
	if err != nil {
		return nil, err
	}
	b64 := base64.StdEncoding.EncodeToString(data)
	md := metadata.Pairs(tokens.METANAME, b64)

	cs.Metadata = ix
	// add our local extension
	nctx := metadata.NewOutgoingContext(ctx, md)
	return nctx, nil
}

func (f *FProxy) rebuildContextFromScratch(a *authResult) error {
	if a == nil {
		return nil
	}
	if rc == nil {
		rc = ic.NewRPCInterceptorServiceClient(client.Connect("rpcinterceptor.RPCInterceptorService"))
	}
	f.md = &ic.InMetadata{
		RequestID:    "", // we want a new one
		UserToken:    "", //do we?
		ServiceToken: tokens.GetServiceTokenParameter(),
	}
	if a != nil && (a.User() != nil) {
		f.SetUser(a.signedUser)
	}
	ireq := &ic.InterceptRPCRequest{Service: "h2gproxy",
		Method:     "createcontext",
		InMetadata: f.md,
	}
	// we need a 'default' context to actually call intercept rpc
	ctx := tokens.ContextWithToken()
	rp, err := rc.InterceptRPC(ctx, ireq)
	if err != nil {
		return err
	}
	nctx, err := createContextWith(ctx, f, a, rp)
	if err != nil {
		return err
	}
	f.ctx = nctx
	if rp != nil {
		f.requestid = rp.RequestID
	}
	return nil
}
