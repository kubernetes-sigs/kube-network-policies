ARG GOARCH="amd64"
FROM golang:1.22 AS builder
WORKDIR /src
COPY . .
# build
RUN go mod download
RUN CGO_ENABLED=0 go build -o /go/bin/netpol ./cmd
# STEP 2: Build small image
FROM registry.k8s.io/build-image/distroless-iptables:v0.5.2
COPY --from=builder --chown=root:root /go/bin/netpol /bin/netpol
CMD ["/bin/netpol"]
