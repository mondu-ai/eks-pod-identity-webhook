# Build stage
FROM golang:1.24-alpine AS builder

# Set up build environment
ARG TARGETOS
ARG TARGETARCH
ARG VERSION
ARG COMMIT
ARG BUILD_DATE

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -a -installsuffix cgo \
    -ldflags="-w -s -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildDate=${BUILD_DATE}" \
    -o eks-pod-identity-webhook \
    ./main.go

# Runtime stage
FROM scratch

# Add metadata labels
LABEL org.opencontainers.image.title="EKS Pod Identity Webhook"
LABEL org.opencontainers.image.description="Kubernetes mutating admission webhook for AWS IAM role assumption in non-EKS clusters"
LABEL org.opencontainers.image.source="https://github.com/mondu-ai/eks-pod-identity-webhook"
LABEL org.opencontainers.image.documentation="https://github.com/mondu-ai/eks-pod-identity-webhook/blob/main/README.md"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.vendor="EKS Pod Identity Webhook Contributors"

# Copy necessary files from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /build/eks-pod-identity-webhook /usr/local/bin/

# Use non-root user for security
USER 65534:65534

# Expose webhook port
EXPOSE 8443

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/eks-pod-identity-webhook"]
