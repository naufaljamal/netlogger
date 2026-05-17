# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM golang:1.24-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o netlogger .

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM alpine:3.20

# ssh client so the app can open sessions to network devices
RUN apk add --no-cache openssh-client ca-certificates tzdata

WORKDIR /app

# Copy binary and UI assets
COPY --from=builder /build/netlogger ./netlogger
COPY static/ ./static/

# logs/ is a temporary staging area — files are uploaded to GitLab then discarded
RUN mkdir -p logs

EXPOSE 8080

ENTRYPOINT ["./netlogger", "--serve", "--addr", ":8080"]
