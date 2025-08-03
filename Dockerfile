# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o auth-service ./cmd/auth-service

# Build the migration tool
WORKDIR /app/migrations
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o migrate .
WORKDIR /app

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binaries from builder stage
COPY --from=builder /app/auth-service .
COPY --from=builder /app/migrations/migrate .

# Copy configuration and assets
COPY --from=builder /app/config.example.yaml ./config.yaml
COPY --from=builder /app/assets ./assets

# Expose port
EXPOSE 8080

# Run the binary
CMD ["./auth-service"] 