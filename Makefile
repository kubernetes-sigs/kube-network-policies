REPO_ROOT:=${CURDIR}
OUT_DIR=$(REPO_ROOT)/bin

# Go build settings
GO111MODULE=on
CGO_ENABLED=0
export GO111MODULE CGO_ENABLED

# Docker image settings
IMAGE_NAME?=kube-network-policies
REGISTRY?=gcr.io/k8s-staging-networking
TAG?=$(shell echo "$$(date +v%Y%m%d)-$$(git describe --always --dirty)")
PLATFORMS?=linux/amd64,linux/arm64

.PHONY: all build build-standard build-npa-v1alpha1 build-npa-v1alpha2 build-iptracker build-kube-ip-tracker-standard

build: build-standard build-npa-v1alpha1 build-npa-v1alpha2 build-iptracker build-kube-ip-tracker-standard

build-standard:
	@echo "Building standard binary..."
	go build -o ./bin/kube-network-policies-standard ./cmd/kube-network-policies/standard

build-npa-v1alpha1:
	@echo "Building npa-v1alpha1 binary..."
	go build -o ./bin/kube-network-policies-npa-v1alpha1 ./cmd/kube-network-policies/npa-v1alpha1

build-npa-v1alpha2:
	@echo "Building npa-v1alpha2 binary..."
	go build -o ./bin/kube-network-policies-npa-v1alpha2 ./cmd/kube-network-policies/npa-v1alpha2

build-iptracker:
	@echo "Building iptracker binary..."
	go build -o ./bin/kube-network-policies-iptracker ./cmd/kube-network-policies/iptracker

build-kube-ip-tracker-standard:
	@echo "Building kube-ip-tracker binary..."
	go build -o ./bin/kube-ip-tracker-standard ./cmd/kube-ip-tracker/standard

clean:
	rm -rf "$(OUT_DIR)/"

test:
	CGO_ENABLED=1 go test -short -v -race -count 1 ./...

lint:
	hack/lint.sh

update:
	go mod tidy

proto:
	hack/generate-proto.sh

.PHONY: ensure-buildx
ensure-buildx:
	./hack/init-buildx.sh

# Individual image build targets (load into local docker)
image-build-standard: build-standard
	docker buildx build . \
		--build-arg TARGET_BUILD=standard \
		--tag="${REGISTRY}/$(IMAGE_NAME):$(TAG)" \
		--load

image-build-npa-v1alpha1: build-npa-v1alpha1
	docker buildx build . \
		--build-arg TARGET_BUILD=npa-v1alpha1 \
		--tag="${REGISTRY}/$(IMAGE_NAME):$(TAG)-npa-v1alpha1" \
		--load

image-build-npa-v1alpha2: build-npa-v1alpha2
	docker buildx build . \
		--build-arg TARGET_BUILD=npa-v1alpha2 \
		--tag="${REGISTRY}/$(IMAGE_NAME):$(TAG)-npa-v1alpha2" \
		--load

image-build-iptracker: build-iptracker
	docker buildx build . \
		--build-arg TARGET_BUILD=iptracker \
		--tag="${REGISTRY}/$(IMAGE_NAME):$(TAG)-iptracker" \
		--load

image-build-kube-ip-tracker-standard: build-kube-ip-tracker-standard
	docker buildx build . -f Dockerfile.iptracker \
		--build-arg TARGET_BUILD=standard \
		--tag="${REGISTRY}/kube-ip-tracker:$(TAG)" \
		--load

# Individual image push targets (multi-platform)
image-push-standard: build-standard
	docker buildx build . \
		--build-arg TARGET_BUILD=standard \
		--platform="${PLATFORMS}" \
		--tag="${REGISTRY}/$(IMAGE_NAME):$(TAG)" \
		--push

image-push-npa-v1alpha1: build-npa-v1alpha1
	docker buildx build . \
		--build-arg TARGET_BUILD=npa-v1alpha1 \
		--platform="${PLATFORMS}" \
		--tag="${REGISTRY}/$(IMAGE_NAME):$(TAG)-npa-v1alpha1" \
		--push

image-push-npa-v1alpha2: build-npa-v1alpha2
	docker buildx build . \
		--build-arg TARGET_BUILD=npa-v1alpha2 \
		--platform="${PLATFORMS}" \
		--tag="${REGISTRY}/$(IMAGE_NAME):$(TAG)-npa-v1alpha2" \
		--push

image-push-iptracker: build-iptracker
	docker buildx build . \
		--build-arg TARGET_BUILD=iptracker \
		--platform="${PLATFORMS}" \
		--tag="${REGISTRY}/$(IMAGE_NAME):$(TAG)-iptracker" \
		--push

image-push-kube-ip-tracker-standard: build-kube-ip-tracker-standard
	docker buildx build . -f Dockerfile.iptracker \
		--build-arg TARGET_BUILD=standard \
		--tag="${REGISTRY}/kube-ip-tracker:$(TAG)" \
		--push

# --- Aggregate Targets ---
.PHONY: images-build images-push release

# Build all image variants and load them into the local Docker daemon
images-build: ensure-buildx image-build-standard image-build-npa-v1alpha1 image-build-npa-v1alpha2 image-build-iptracker image-build-kube-ip-tracker-standard

# Build and push all multi-platform image variants to the registry
images-push: ensure-buildx image-push-standard image-push-npa-v1alpha1 image-build-npa-v1alpha2 image-push-iptracker image-push-kube-ip-tracker-standard

# The main release target, which pushes all images
release: images-push