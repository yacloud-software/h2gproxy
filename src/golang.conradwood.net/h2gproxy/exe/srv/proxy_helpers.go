package srv

import (
	h2g "golang.conradwood.net/apis/h2gproxy"
)

func AddUserHeaders1(f *FProxy, sv *h2g.ServeRequest) error {
	ms, err := f.createUserHeaders()
	if err != nil {
		return err
	}
	for k, v := range ms {
		sv.Headers = append(sv.Headers, &h2g.Header{Name: k, Values: []string{v}})
	}
	return nil
}
func AddUserHeaders2(f *FProxy, sv *h2g.StreamRequest) error {
	ms, err := f.createUserHeaders()
	if err != nil {
		return err
	}
	for k, v := range ms {
		sv.Headers = append(sv.Headers, &h2g.Header{Name: k, Values: []string{v}})
	}
	return nil
}
