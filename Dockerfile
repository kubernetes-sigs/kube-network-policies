FROM --platform=$BUILDPLATFORM golang:1.24 AS builder

WORKDIR /src

COPY go.mod go.sum .
RUN go mod download

COPY . .

ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -o /go/bin/netpol ./cmd

# STEP 2: Build small image
FROM gcr.io/distroless/static-debian12
COPY --from=builder --chown=root:root /go/bin/netpol /bin/netpol

CMD ["/bin/netpol"]
