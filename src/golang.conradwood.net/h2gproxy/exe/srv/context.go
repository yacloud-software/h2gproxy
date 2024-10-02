package srv

import (
	"context"
	"fmt"

	//	"encoding/base64"
	"flag"
	//	"fmt"
	//	"github.com/golang/protobuf/proto"
	"golang.conradwood.net/go-easyops/authremote"
	"golang.conradwood.net/go-easyops/ctx/shared"

	//	"golang.conradwood.net/go-easyops/client"

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

// used e.g. by grpcproxy
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
	cb := ctx.NewContextBuilder()
	cb.WithTimeout(time.Duration(secs) * time.Second)
	cb.WithSession(f.session)
	cb.WithUser(f.signeduser)
	cb.WithRequestID(f.GetRequestID())
	cb.WithCallingService(authremote.GetLocalServiceAccount())
	f.addContextFlags(cb)
	return cb.ContextWithAutoCancel(), nil

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
	f.addContextFlags(cb)
	ctx := cb.ContextWithAutoCancel()
	return ctx, nil
}
func (f *FProxy) rebuildContextFromScratch(a *authResult) error {
	if a == nil {
		return nil
	}

	if a != nil && (a.User() != nil) {
		f.SetUser(a.signedUser)
	}

	_, svc := authremote.GetLocalUsers()
	cb := ctx.NewContextBuilder()
	cb.WithUser(a.signedUser)
	cb.WithCallingService(svc)
	cb.WithCreatorService(svc)
	cb.WithSession(f.session)
	f.addContextFlags(cb)
	f.ctx = cb.ContextWithAutoCancel()
	return nil

}
func (f *FProxy) addContextFlags(cb shared.ContextBuilder) {
	if f.IsReleased() {
		// body/form no longer available
		return
	}
	if f.GetUser() == nil {
		return
	}
	vals := f.RequestValues()
	if vals["ge_debug"] == "true" {
		if *debugctx {
			fmt.Printf("[context] setting debug to true\n")
		}
		cb.WithDebug()
	}
	if vals["ge_trace"] == "true" {
		if *debugctx {
			fmt.Printf("[context] setting trace to true\n")
		}
		cb.WithTrace()
	}
	ex := vals["ge_experiment"]
	if ex != "" {
		if *debugctx {
			fmt.Printf("[context] enabling experiment \"%s\"\n", ex)
		}
		cb.EnableExperiment(ex)
	}
}
