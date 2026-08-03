# Multi-stage Dockerfile for Authpole Go Server

# Stage 1: Build stage
FROM golang:alpine AS builder

WORKDIR /build

# Copy source code and module files
COPY go.mod go.sum ./
COPY cmd/ ./cmd/
COPY pkg/ ./pkg/

# Build static Go binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /build/authpole ./cmd/server

# Stage 2: Runtime stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/authpole /app/authpole

# Expose server port
EXPOSE 8080

# Run Authpole server
ENTRYPOINT ["/app/authpole"]
