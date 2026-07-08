# runeward control plane, MCP server, and Kubernetes controller (one binary).
FROM --platform=$BUILDPLATFORM golang:1.25@sha256:f188e8c16ea47a8b22d2bdcf6d9bcd07b63ea7876c199749c07bf31e0ab33bad AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -ldflags "-s -w -X github.com/Runewardd/runeward/internal/cli.version=${VERSION}" \
    -o /out/runeward ./cmd/runeward

FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639
LABEL org.opencontainers.image.source="https://github.com/Runewardd/runeward"
LABEL org.opencontainers.image.description="Governed execution cells for AI agents"
# MCP registry OCI ownership check: the value MUST equal the server.json "name".
LABEL io.modelcontextprotocol.server.name="io.github.Runewardd/runeward"
COPY --from=build /out/runeward /usr/local/bin/runeward
ENTRYPOINT ["/usr/local/bin/runeward"]
CMD ["serve", "--port", "8080"]
