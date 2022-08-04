module golang.conradwood.net/h2gproxy

go 1.18

require (
	github.com/dustin/go-humanize v1.0.0
	github.com/golang/protobuf v1.5.2
	golang.conradwood.net/apis/antidos v1.1.1784
	golang.conradwood.net/apis/auth v1.1.1784
	golang.conradwood.net/apis/certmanager v1.1.1784
	golang.conradwood.net/apis/common v1.1.1784
	golang.conradwood.net/apis/framework v1.1.1784
	golang.conradwood.net/apis/h2gproxy v1.1.1746
	golang.conradwood.net/apis/httpkpi v1.1.1784
	golang.conradwood.net/apis/jsonapimultiplexer v1.1.1784
	golang.conradwood.net/apis/registry v1.1.1784
	golang.conradwood.net/apis/rpcinterceptor v1.1.1784
	golang.conradwood.net/apis/usagestats v1.1.1784
	golang.conradwood.net/apis/weblogin v1.1.1784
	golang.conradwood.net/go-easyops v0.1.12984
	golang.org/x/net v0.0.0-20220802222814-0bcc04d9c69b
	google.golang.org/grpc v1.48.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/prometheus/client_golang v1.12.2 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.37.0 // indirect
	github.com/prometheus/procfs v0.8.0 // indirect
	golang.conradwood.net/apis/autodeployer v1.1.1784 // indirect
	golang.conradwood.net/apis/deploymonkey v1.1.1784 // indirect
	golang.conradwood.net/apis/echoservice v1.1.1784 // indirect
	golang.conradwood.net/apis/errorlogger v1.1.1784 // indirect
	golang.conradwood.net/apis/objectstore v1.1.1784 // indirect
	golang.org/x/sys v0.0.0-20220803195053-6e608f9ce704 // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/genproto v0.0.0-20220803205849-8f55acc8769f // indirect
	google.golang.org/protobuf v1.28.1 // indirect
)

replace golang.conradwood.net/apis/h2gproxy => ../../golang.conradwood.net/apis/h2gproxy
