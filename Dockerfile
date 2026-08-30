FROM golang:1.27.0-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/control-plane ./cmd/control-plane

FROM scratch
COPY --from=build /out/control-plane /control-plane
COPY LICENSE /LICENSE
ENV LISTEN_ADDRESS=0.0.0.0:8080
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/control-plane"]
