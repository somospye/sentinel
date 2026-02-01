# Builder
FROM golang:1.25.6 AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libstdc++6 \
    libgcc1 \
    libgomp1 \
    libgfortran5 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN go mod tidy

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -o sentinel main.go

# Runner
FROM arm64v8/debian:bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libstdc++6 \
    libgcc1 \
    libgomp1 \
    libgfortran5 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/sentinel .

COPY --from=builder /app/assets ./assets

CMD ["./sentinel"]
