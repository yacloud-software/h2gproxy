#!/bin/sh
. ~/yacloud-scripts/private/bash.private

module-stop localhost:4177 
make server || exit 10
sudo ${GOBIN}/h2gproxy-server -registry=localhost -token=${H2GPROXY_TOKEN} -config_file=${HOME}/devel/go/h2gproxy/configs/cnw.yaml -port=4177 -http_port=80 -https_port=443 -enable_histogram=true -enable_basic_auth=true -enable_raw_paths=true -log_each_request=false -registry_resolver=localhost -ge_dialer_sleep_time=1 -ge_deployment_descriptor=V1:h2gproxy/testing/h2gproxy/100000 -disable_tcp -debug -print_headers -log_each_request -debug_grpc_proxy -print_timing -activate_probe_backend
