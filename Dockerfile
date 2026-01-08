# Use an ARG to select which build target to compile and use
ARG TARGET_BUILD=standard

FROM --platform=$BUILDPLATFORM golang:1.25 AS builder
WORKDIR /src

# Get target architecture for cross-compilation
ARG TARGETOS
ARG TARGETARCH
ARG TARGET_BUILD

COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Build the specific binary based on the build argument and target architecture
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} make build-${TARGET_BUILD}

# STEP 2: Build small image
FROM gcr.io/distroless/static-debian12
ARG TARGET_BUILD
COPY --from=builder /src/bin/kube-network-policies-${TARGET_BUILD} /bin/netpol

# The entrypoint is always the same, regardless of the build
CMD ["/bin/netpol"]