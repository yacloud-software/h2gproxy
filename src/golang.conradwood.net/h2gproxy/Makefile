.PHONY:	client server probe
all:	client server probe
server:
	cd server && go install ${LDFLAGS} h2gproxy-server.go `ls -1 *.go |grep -v h2gproxy-server.go`
probe:
	cd probe/cmdline && go install ${LDFLAGS} h2gproxy-probe.go `ls -1 *.go |grep -v h2gproxy-probe.go`
client:
	cd client && go install ${LDFLAGS} h2gproxy-client.go
