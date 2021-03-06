package main

import (
	"context"
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

func pw_key(req *apb.AuthenticatePasswordRequest) string {
	return req.Email + "/" + req.Password
}
