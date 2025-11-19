# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /src

# Copy source code and go mod files
COPY . .

# Download dependencies
RUN go mod download

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o rbldnsd .

# Final stage - distroless
FROM gcr.io/distroless/base-debian12:nonroot

# Copy binary from builder
COPY --from=builder /src/rbldnsd /usr/local/bin/rbldnsd

# Copy entrypoint script
COPY --from=builder /src/entrypoint.sh /entrypoint.sh

# Create volumes
VOLUME ["/data", "/config"]

# Default port for DNS
EXPOSE 53/udp

# Default config path
ENV CONFIG_PATH=/config/rbldnsd.yaml

# Use entrypoint script for flexible configuration
ENTRYPOINT ["/entrypoint.sh"]

# Default command (can be overridden)
CMD ["-n"]
