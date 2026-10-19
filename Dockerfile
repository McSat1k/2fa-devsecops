
# Stage 1: Build the Go application
FROM golang:1.26-bookworm AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /app/server .

# Stage 2: Run the application
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/server /app/server
COPY --from=builder /app/templates /app/templates

RUN mkdir -p /app/data

EXPOSE 8080

CMD ["/app/server"]
