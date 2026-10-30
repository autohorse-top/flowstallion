# FlowStallion — single image containing both Go binaries (scheduler + agent).
#
# Build:  docker build -t flowstallion:latest .
# Usage:  docker compose up -d --build   (see docker-compose.yml)
#
# The agent container talks to the *host* Docker daemon through the mounted
# socket, so the host must be running Docker (or colima) and the pipeline's
# step images must be pullable/runnable by that daemon.

FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY pkg/ ./pkg/
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/scheduler ./cmd/scheduler \
 && CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/agent     ./cmd/agent \
 && CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/flowstallion        ./cmd/flowstallion

FROM alpine:3.20
RUN apk add --no-cache ca-certificates docker-cli
COPY --from=build /out/scheduler /usr/local/bin/scheduler
COPY --from=build /out/agent     /usr/local/bin/agent
COPY --from=build /out/flowstallion        /usr/local/bin/flowstallion
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
