# whoami

The service behind `whoami.<domain>`: it shows visitors the identity any
website can assign to their browser without cookies, and whether that identity
survives private windows, other browsers and VPNs.

It terminates TLS itself (behind nginx's SNI router, which forwards the raw
stream with a PROXY protocol header), so besides the ~40 signals the page
collects it sees what normally only CDNs and bot-detection services see: the
TLS ClientHello (JA4, JA3) and the opening of the HTTP/2 connection (Akamai
format).

Standard library only; no third-party Go modules.

| Path | Contents |
|---|---|
| `internal/netfp` | PROXY protocol, TLS listener that records the ClientHello, JA3/JA4, HTTP/2 frame parsing, certificate hot reload |
| `internal/geo` | MaxMind DB reader, DB-IP Lite downloader, Tor exit list, time zones by country, hosting/VPN networks |
| `internal/store` | Identity store: keyed hashes only, retention, eviction, forget |
| `internal/persona` | Name, animal, colours, rosette and passport MRZ derived from an identifier |
| `*.go` | HTTP handlers, attribute registry, consistency checks, User-Agent parsing |
| `web/` | Page template, collector (`collect.js`), page logic, styles, self-hosted fonts and FingerprintJS |

## Run locally

```bash
WHOAMI_SELF_SIGNED=true WHOAMI_PROXY_PROTOCOL=false WHOAMI_HOSTNAME=localhost \
WHOAMI_DATA_DIR=./data WHOAMI_LISTEN=127.0.0.1:8443 go run .
# https://localhost:8443 (accept the self-signed certificate)
go test ./...
```

The first start downloads the DB-IP Lite databases (about 140 MB) and the Tor
exit list into the data directory; `WHOAMI_GEOIP=off` and `WHOAMI_TOR=false`
skip them.

## Configuration

| Variable | Default | |
|---|---|---|
| `WHOAMI_HOSTNAME` | | Public name; requests for other hosts get 421 |
| `WHOAMI_LISTEN` | `:8443` | TLS listener |
| `WHOAMI_PROXY_PROTOCOL` | `true` | Require a PROXY protocol header (v1 or v2) |
| `WHOAMI_CERT_FILE`, `WHOAMI_KEY_FILE` | | PEM files, reloaded when they change |
| `WHOAMI_SELF_SIGNED` | `false` | Generate a certificate instead (development) |
| `WHOAMI_DATA_DIR` | `/data` | Secret, store, location databases, Tor list |
| `WHOAMI_RETENTION_DAYS` | `180` | Days a fingerprint is kept after its last scan |
| `WHOAMI_MAX_BROWSERS` | `50000` | Store size cap; the oldest records go first |
| `WHOAMI_GEOIP` | `city` | DB-IP Lite edition: `city`, `country` or `off` |
| `WHOAMI_TOR` | `true` | Fetch the Tor exit list hourly |
| `WHOAMI_STUN` | `stun:stun.cloudflare.com:3478` | Used only when a visitor runs the WebRTC test |
| `WHOAMI_HEALTH_LISTEN` | `127.0.0.1:8081` | Plain HTTP `/healthz` for the container health check |
| `WHOAMI_DEBUG` | `false` | Log failed handshakes and PROXY headers |

## Privacy

Nothing is stored until the visitor presses Scan. A scan stores, per browser
fingerprint, HMAC-SHA256 values under a secret generated on first start
(`secret.key`): one per attribute value, one for the device identity, one for
the IP address; plus first and last scan time, a visit count and a coarse
label such as "Firefox 155 on Linux". No raw values, IP addresses or
User-Agent strings are written. Records expire `WHOAMI_RETENTION_DAYS` after
the last scan, and "Forget this browser" deletes them at once. The cookie
holds a random identifier, stored hashed. Server logs record nothing per
request.

## Sources and licenses

- Location and network: [DB-IP](https://db-ip.com) Lite, CC BY 4.0, refreshed monthly; attribution is on the page.
- Tor exits: https://check.torproject.org/torbulkexitlist, hourly.
- [FingerprintJS](https://github.com/fingerprintjs/fingerprintjs) 5.3.0, MIT, vendored in `web/static/vendor` and loaded with its telemetry disabled.
- Atkinson Hyperlegible Next and Mono, SIL OFL 1.1, in `web/static/fonts`.
- JA4 (TLS client) follows FoxIO's specification, BSD 3-Clause; test vectors come from their repository (see `internal/netfp/testdata`). JA3 follows Salesforce's original definition.
