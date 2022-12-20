package srv

import (
	"context"
	"fmt"
	apb "golang.conradwood.net/apis/auth"
	"golang.conradwood.net/go-easyops/cache"
	"time"
)

var (
	auth_bypw = cache.New("h2gproxy_authcache_bypw", time.Duration(60)*time.Second, 100)
)

type authServerProxy struct {
}

func NewAuthServerProxy() *authServerProxy {
	res := &authServerProxy{}
	return res
}

func (asp *authServerProxy) SignedGetByPassword(ctx context.Context, req *apb.AuthenticatePasswordRequest) (*apb.SignedAuthResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("authproxy.SignedGetByPassword() called without request")
	}
	key := pw_key(req)
	cra := auth_bypw.Get(key)
	if cra != nil {
		return cra.(*apb.SignedAuthResponse), nil
	}
	cr, err := AuthServer.SignedGetByPassword(ctx, req)
	if err == nil {
		auth_bypw.Put(key, cr)
	}
	return cr, err
}

// TODO: cache this as well
func (asp *authServerProxy) SignedGetByToken(ctx context.Context, req *apb.AuthenticateTokenRequest) (*apb.SignedAuthResponse, error) {
	cr, err := AuthServer.SignedGetByToken(ctx, req)
	return cr, err
}
func pw_key(req *apb.AuthenticatePasswordRequest) string {
	return req.Email + "/" + req.Password
}
