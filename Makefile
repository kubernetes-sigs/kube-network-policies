REPO_ROOT:=${CURDIR}
OUT_DIR=$(REPO_ROOT)/bin
BINARY_NAME?=kube-network-policies

# go1.9+ can autodetect GOROOT, but if some other tool sets it ...
GOROOT:=
# enable modules
GO111MODULE=on
# disable CGO by default for static binaries
CGO_ENABLED=0
export GOROOT GO111MODULE CGO_ENABLED


build:
	go build -v -o "$(OUT_DIR)/$(BINARY_NAME)" $(KIND_CLOUD_BUILD_FLAGS) cmd/kube-network-policies/main.go
	go build -v -o "$(OUT_DIR)/kube-ip-tracker" $(KIND_CLOUD_BUILD_FLAGS) cmd/kube-ip-tracker/main.go

clean:
	rm -rf "$(OUT_DIR)/"

test:
	CGO_ENABLED=1 go test -v -race -count 1 ./...

# code linters
lint:
	hack/lint.sh

update:
	go mod tidy

# Generate Go code from the proto definition
proto:
	hack/generate-proto.sh

# get image name from directory we're building
IMAGE_NAME=kube-network-policies
# docker image registry, default to upstream
REGISTRY?=gcr.io/k8s-staging-networking
# tag based on date-sha
TAG?=$(shell echo "$$(date +v%Y%m%d)-$$(git describe --always --dirty)")
# the full image tag
KNP_IMAGE?=$(REGISTRY)/$(IMAGE_NAME):$(TAG)
PLATFORMS?=linux/amd64,linux/arm64

.PHONY: ensure-buildx
ensure-buildx:
	./hack/init-buildx.sh
	
image-build:
	docker buildx build . \
		--tag="${KNP_IMAGE}" \
		--load

image-push:
	docker buildx build . \
		--platform="${PLATFORMS}" \
		--tag="${KNP_IMAGE}" \
		--push

.PHONY: release # Build a multi-arch docker image
release: ensure-buildx image-push
