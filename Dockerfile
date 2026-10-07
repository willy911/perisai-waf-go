# Build stage
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO dimatikan: modernc.org/sqlite murni Go (tanpa cgo)
RUN CGO_ENABLED=0 go build -trimpath -o /out/perisai ./cmd/perisai && \
    CGO_ENABLED=0 go build -trimpath -o /out/perisai-setpassword ./cmd/setpassword

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates bash \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /out/perisai /out/perisai-setpassword /app/
# Dashboard Svelte (prebuilt) + contoh config
COPY ui/dist /app/ui/dist
COPY config.example.yaml /app/config.example.yaml
# Default siap jalan tanpa file config (semua via environment, ala 9router).
ENV DATA_DIR=/app/data \
    PORT=8080 \
    DASHBOARD_PORT=8899 \
    HOSTNAME=0.0.0.0
VOLUME ["/app/data"]
EXPOSE 8080 8899
# Healthcheck tanpa curl: bash /dev/tcp ke port dashboard.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD bash -c '</dev/tcp/127.0.0.1/${DASHBOARD_PORT:-8899}' || exit 1
ENTRYPOINT ["/app/perisai"]
CMD ["--config", "/app/config.yaml"]
