# Build stage
FROM golang:1.25-alpine AS builder

# Build arguments for version information
ARG VERSION=""
ARG GIT_HASH=""
ARG BRANCH=""

WORKDIR /build

# Copy source code and go mod files
COPY . .

# Download dependencies
RUN go mod download

# Build the binary with version information
# -s -w strips debug symbols for a smaller binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.GitHash=${GIT_HASH} -X main.Branch=${BRANCH}" \
    -o rbldnsd .

# Final stage - Chainguard static: zero known CVEs, rebuilt nightly,
# non-root by default (UID 65532), no shell, no package manager.
FROM cgr.dev/chainguard/static:latest

# Copy binary from builder
COPY --from=builder /build/rbldnsd /usr/local/bin/rbldnsd

# Create volumes
VOLUME ["/data", "/config"]

# Default port for DNS
EXPOSE 53/udp

# Default config path
ENV CONFIG_PATH=/config/rbldnsd.yaml

# Use the binary directly with config file
ENTRYPOINT ["/usr/local/bin/rbldnsd"]
CMD ["-c", "/config/rbldnsd.yaml"]
