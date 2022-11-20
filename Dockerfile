# syntax=docker/dockerfile:1.1.7-experimental

# Base Go environment
# -------------------
FROM --platform=${BUILDPLATFORM} golang:1.19.3-bullseye as base
WORKDIR /porter

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
COPY /api ./api
COPY /cli ./cli
COPY /internal ./internal
COPY /pkg ./pkg


# Go build environment
# --------------------
FROM base AS build-go

# build proto files
ARG version=production

# cgo is enabled because sqlite package we use requires it.
RUN CGOENABLED=1 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -a -o ./bin/agent .
RUN CGOENABLED=1 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -a -o ./bin/agent-cli ./cli

# Deployment environment
# ----------------------
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y ca-certificates

COPY --from=build-go /porter/bin/agent /porter/
COPY --from=build-go /porter/bin/agent-cli /porter/

ENV SERVER_PORT=10001
ENV SERVER_TIMEOUT_READ=5s
ENV SERVER_TIMEOUT_WRITE=10s
ENV SERVER_TIMEOUT_IDLE=15s

EXPOSE 10001
CMD /porter/agent
