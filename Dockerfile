FROM --platform=$BUILDPLATFORM golang:1.23 AS builder

WORKDIR /src

COPY go.mod go.sum .
RUN --mount=type=cache,target=/go/pkg \
    go mod download

COPY . .

ARG TARGETOS TARGETARCH
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -o /go/bin/netpol ./cmd

# STEP 2: Build small image
FROM registry.k8s.io/build-image/distroless-iptables:v0.6.5
COPY --from=builder --chown=root:root /go/bin/netpol /bin/netpol

CMD ["/bin/netpol"]
