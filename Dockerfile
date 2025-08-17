
FROM --platform=$BUILDPLATFORM golang:1.24 AS plugin-builder
WORKDIR /src
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    make build-plugins

FROM --platform=$BUILDPLATFORM golang:1.24 AS builder
WORKDIR /src
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -o /go/bin/netpol ./cmd

# STEP 2: Build small image
FROM gcr.io/distroless/static-debian12
COPY --from=builder --chown=root:root /go/bin/netpol /bin/netpol
# Copy the built plugins into the final image
COPY --from=plugin-builder /src/bin/plugins /var/lib/kube-network-policies/plugins

CMD ["/bin/netpol", "--plugin-dir=/var/lib/kube-network-policies/plugins"]
