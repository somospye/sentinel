# Builder
FROM golang:1.25.6-alpine AS builder

WORKDIR /app

RUN apk add --no-cache gcc musl-dev

COPY go.mod go.sum ./
RUN go mod tidy

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -o sentinel main.go

# Runner
FROM alpine:latest

WORKDIR /app

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/sentinel .

COPY --from=builder /app/assets ./assets

CMD ["./sentinel"]
