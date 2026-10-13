# Built on the edge node by the whoami role. The Go version is pinned
# exactly and updated by pull request; changing this file changes the image
# tag, so the next playbook run rebuilds and redeploys.
FROM golang:1.27.2-alpine AS build
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/whoami .

# No shell, no package manager: the binary, CA roots for the data feeds,
# and nothing else. Time zone data is compiled into the binary.
FROM scratch
LABEL io.pavel-zin.service="whoami" \
      org.opencontainers.image.source="https://github.com/pavel-zin/infra-platform"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/whoami /whoami
EXPOSE 8443
ENTRYPOINT ["/whoami"]
