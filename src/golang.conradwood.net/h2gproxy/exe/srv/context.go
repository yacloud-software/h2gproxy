package srv

import (
	"context"
	//	"encoding/base64"
	"flag"
	//	"fmt"
	//	"github.com/golang/protobuf/proto"
	"golang.conradwood.net/go-easyops/authremote"
	//	"golang.conradwood.net/go-easyops/client"
	"golang.conradwood.net/go-easyops/cmdline"
	"golang.conradwood.net/go-easyops/ctx"
	//	"golang.conradwood.net/go-easyops/rpc"
	//	"golang.conradwood.net/go-easyops/tokens"
	//	"google.golang.org/grpc/metadata"
	"time"
)

var (
	debugctx = flag.Bool("debug_ctx", false, "debug context transformations and user metadata")
)

// create a context that may be used to call rpcinterceptor
func createBootstrapContext() context.Context {
	//	return authremote.Context()
	return authremote.Context()
}

func createContext(f *FProxy, a *authResult) (context.Context, error) {
	secs := f.hf.def.MaxDuration
	if secs == 0 {
		if f.Api() == 4 {
			secs = 600 // streaming is longer by default
		} else {
			secs = 10
		}
	}
	u := a.SignedUser()
	if u != nil {
		f.SetUser(u)
	}
	if cmdline.ContextWithBuilder() { // true for any recent (spring '23)  go-easyops version
		cb := ctx.NewContextBuilder()
		cb.WithTimeout(time.Duration(secs) * time.Second)
		cb.WithSession(f.session)
		cb.WithUser(f.signeduser)
		cb.WithRequestID(f.GetRequestID())
		cb.WithCallingService(authremote.GetLocalServiceAccount())
		return cb.ContextWithAutoCancel(), nil
	}
	//	octx := tokens.ContextWithTokenAndTimeout(uint64(secs))
	octx := authremote.ContextWithTimeout(time.Duration(secs) * time.Second)
	return createContextWith(octx, f, a)
}

func createCancellableContext(f *FProxy, a *authResult) (context.Context, context.CancelFunc, error) {
	secs := f.hf.def.MaxDuration
	if secs == 0 {
		if f.Api() == 4 {
			secs = 600 // streaming is longer by default
		} else {
			secs = 10
		}
	}
	cb := ctx.NewContextBuilder()
	cb.WithTimeout(time.Duration(secs) * time.Second)
	if a.signedUser != nil {
		cb.WithUser(a.signedUser)
	} else {
		cb.WithUser(f.signeduser)
	}

	cb.WithCallingService(authremote.GetLocalServiceAccount())
	cb.WithCreatorService(authremote.GetLocalServiceAccount())
	cb.WithSession(f.session)
	octx, cnc := cb.Context()
	//	octx, cnc := tokens.Context2WithTokenAndTimeout(uint64(secs))
	ctx, err := createContextWith(octx, f, a)
	if err != nil {
		return nil, nil, err
	}
	return ctx, cnc, nil
}

func createContextWith(octx context.Context, f *FProxy, a *authResult) (context.Context, error) {
	if octx.Err() != nil {
		// no point calling out with a failed context
		return nil, octx.Err()
	}
	if cmdline.ContextWithBuilder() {
		cb := ctx.NewContextBuilder()
		cb.WithParentContext(octx)
		if a.signedUser != nil {
			cb.WithUser(a.signedUser)
		} else {
			cb.WithUser(f.signeduser)
		}
		cb.WithCallingService(authremote.GetLocalServiceAccount())
		cb.WithCreatorService(authremote.GetLocalServiceAccount())
		cb.WithSession(f.session)
		ctx := cb.ContextWithAutoCancel()
		return ctx, nil
	}
	panic("only with contextbuilder")
	/*
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
	*/
}

func (f *FProxy) rebuildContextFromScratch(a *authResult) error {
	if a == nil {
		return nil
	}

	if a != nil && (a.User() != nil) {
		f.SetUser(a.signedUser)
	}

	if cmdline.ContextWithBuilder() {
		_, svc := authremote.GetLocalUsers()
		cb := ctx.NewContextBuilder()
		cb.WithUser(a.signedUser)
		cb.WithCallingService(svc)
		cb.WithCreatorService(svc)
		cb.WithSession(f.session)
		f.ctx = cb.ContextWithAutoCancel()
		return nil
	}
	panic("context builder only")
	/*
		if rc == nil {
			rc = ic.NewRPCInterceptorServiceClient(client.Connect("rpcinterceptor.RPCInterceptorService"))
		}
		f.md = &ic.InMetadata{
			RequestID:    "", // we want a new one
			UserToken:    "", //do we?
			ServiceToken: tokens.GetServiceTokenParameter(),
		}

		ireq := &ic.InterceptRPCRequest{Service: "h2gproxy",
			Method:     "createcontext",
			InMetadata: f.md,
		}
		// we need a 'default' context to actually call intercept rpc
		ctx := authremote.Context()
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
	*/
}
