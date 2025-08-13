#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

REPO_ROOT=$(dirname "${BASH_SOURCE[0]}")/..

cd $REPO_ROOT
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
protoc --go_out=paths=source_relative:. --go-grpc_out=paths=source_relative:. pkg/api/kubenetworkpolicies.proto
