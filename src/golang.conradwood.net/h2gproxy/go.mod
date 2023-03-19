module golang.conradwood.net/h2gproxy

go 1.18

require (
	github.com/dustin/go-humanize v1.0.1
	golang.conradwood.net/apis/antidos v1.1.2210
	golang.conradwood.net/apis/auth v1.1.2210
	golang.conradwood.net/apis/certmanager v1.1.2210
	golang.conradwood.net/apis/common v1.1.2210
	golang.conradwood.net/apis/framework v1.1.2210
	golang.conradwood.net/apis/h2gproxy v1.1.1746
	golang.conradwood.net/apis/jsonapimultiplexer v1.1.2210
	golang.conradwood.net/apis/registry v1.1.2210
	golang.conradwood.net/apis/rpcinterceptor v1.1.2210
	golang.conradwood.net/apis/usagestats v1.1.2210
	golang.conradwood.net/apis/weblogin v1.1.2210
	golang.conradwood.net/go-easyops v0.1.16745
	golang.org/x/net v0.8.0
	golang.yacloud.eu/apis/session v1.1.2210
	golang.yacloud.eu/apis/sessionmanager v1.1.2210
	google.golang.org/grpc v1.53.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/prometheus/client_golang v1.14.0 // indirect
	github.com/prometheus/client_model v0.3.0 // indirect
	github.com/prometheus/common v0.42.0 // indirect
	github.com/prometheus/procfs v0.9.0 // indirect
	golang.conradwood.net/apis/autodeployer v1.1.2210 // indirect
	golang.conradwood.net/apis/deploymonkey v1.1.2210 // indirect
	golang.conradwood.net/apis/echoservice v1.1.2210 // indirect
	golang.conradwood.net/apis/errorlogger v1.1.2210 // indirect
	golang.conradwood.net/apis/goeasyops v1.1.2210 // indirect
	golang.conradwood.net/apis/objectstore v1.1.2210 // indirect
	golang.org/x/sys v0.6.0 // indirect
	golang.org/x/text v0.8.0 // indirect
	golang.yacloud.eu/apis/urlcacher v1.1.2210 // indirect
	google.golang.org/genproto v0.0.0-20230110181048-76db0878b65f // indirect
	google.golang.org/protobuf v1.30.0 // indirect
)

replace golang.conradwood.net/apis/h2gproxy => ../../golang.conradwood.net/apis/h2gproxy
