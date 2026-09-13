# Configuration and HTTP behavior

[Documentation index](DOCUMENTATION.md) · [Project README](README.md)

Startup configuration rejects invalid inputs before creating the collector or listener. `-web.debug-log-level.enable` controls registration of the runtime log-level endpoint. Attached-volume retype monitoring is separately opt-in through `-volume.retype.enable`.

**On this page**

- [Default versus explicit operator intent](#default-versus-explicit-operator-intent)
- [Optional retype monitoring](#optional-retype-monitoring)
- [Directions, URLs, files, and interfaces](#directions-urls-files-and-interfaces)
- [Runtime log-level endpoint](#runtime-log-level-endpoint)
- [HTTP resource limits](#http-resource-limits)
- [Compatibility boundary](#compatibility-boundary)
- [Acceptance guarantees](#acceptance-guarantees)

## Default versus explicit operator intent

A documented default is used only when its flag is omitted. If an operator supplies a value, that value is validated and is never clamped, replaced with a default, or silently broadened. An invalid value is a startup configuration error and exits with status `2` before collector creation or listener startup. Unknown flags and invalid flag syntax also exit with status `2`.

The default listen address remains `0.0.0.0:9120` for compatibility when `-web.listen-address` is omitted. An explicitly supplied listen address is passed to the listener exactly as configured: an empty address is rejected and a bind or address-resolution failure exits with runtime status `1`; there is no retry on `0.0.0.0`.

The following exact boundaries apply:

| Setting | Default | Accepted configuration |
| --- | ---: | --- |
| `behavior.sensitivity` | `1.0` | Any finite value from `0.1` through `10.0`, inclusive. Exact bounds are accepted; values outside them are rejected rather than clamped. |
| `severity.weight.resource` | `0.45` | Finite and non-negative. |
| `severity.weight.behavior` | `0.45` | Finite and non-negative. |
| `severity.weight.threat_list` | `0.10` | Finite and non-negative. |
| Combined severity weights | `1.0` | Individual zeroes are allowed, but all three weights may not be zero and their sum must remain finite. |
| `collection.interval` | `15s` | `5s` through `1m`, inclusive. |
| `worker.count` | `0` | Integer `0` through `64`, inclusive. `0` selects `NumCPU`, capped at `64`; `1` through `64` are exact. |
| `behavior.ewma_fast_tau` | `3m` | Greater than zero and strictly less than `behavior.ewma_slow_tau`. |
| `behavior.ewma_slow_tau` | `2h` | Greater than zero and strictly greater than `behavior.ewma_fast_tau`. |
| `threat.ewma_tau` | `2m30s` | Greater than zero. |
| `conntrack.raw.rcvbuf_bytes` | `33554432` | Integer zero or greater. |
| `conntrack.raw.rcv_timeout` | `15s` | Greater than zero. |
| `threat.log.min_interval` | `5m` | Zero or greater. Zero remains the explicit opt-out from repeat throttling. |

`NaN`, positive infinity, and negative infinity are rejected for every floating-point scalar. A finite set of individually valid severity weights is also rejected if adding the weights overflows to infinity.

`-log.level` defaults to `info`. Its accepted values are exactly `debug`, `info`, `warn`, `notice`, and `error`, after trimming surrounding whitespace and folding case. `notice` is the existing alias for `warn`. A blank or unsupported explicit value is rejected; it is not changed to `info` for a running exporter.

## Optional retype monitoring

`-volume.retype.enable` defaults to `false`; passing the flag or `-volume.retype.enable=true` enables attached-volume retype monitoring. Omission or `-volume.retype.enable=false` disables dedicated discovery, the active-job poller and all retype metric samples. This startup setting does not disable the ordinary Libvirt collection safeguards. The Ansible equivalent is `openstack_instance_exporter_volume_retype_enable: true`; every role profile leaves it off unless explicitly enabled.

## Directions, URLs, files, and interfaces

### Contact direction

The default contact direction accepts canonical `out`, `in`, or `any`, plus the existing compatibility aliases `outbound`/`src` and `inbound`/`dst`, after trimming surrounding whitespace and folding case. A per-feed direction may use the exact empty default to inherit the validated contact direction; a non-empty value accepts the same canonical values and aliases. A whitespace-only per-feed value and all other invalid direction text stop startup.

### Feed URLs and refresh intervals

An enabled network feed requires an HTTP or HTTPS URL with a non-empty host and no embedded user information or credentials. Leading or trailing whitespace, another scheme, a missing hostname, or embedded credentials are rejected. An explicitly supplied feed URL or refresh flag is validated even when that feed is disabled, so a bad configured value cannot hide behind an enable flag. Network-feed and custom-list refresh values must be zero or greater; zero keeps the existing one-shot behavior. Enabled Spamhaus requires at least one non-empty, valid IPv4 or IPv6 feed URL.

### Local inputs and interfaces

Configured local inputs have these exact semantics:

#### Behavior YAML files

Behavior YAML inputs must be stable regular files no larger than 1 MiB. A FIFO, device, oversized file, explicit YAML `null`, or file that changes while it is read is rejected without an unbounded startup read.

#### Monitored-port file

With `behavior.ports_config` unset, the built-in inbound and outbound port maps are used. A valid file replaces each direction it defines, including with an explicitly empty map, and leaves the omitted direction on its built-in map. A configured file that is missing, unreadable, empty, malformed, contains unknown fields or multiple YAML documents, defines no map, or contains an invalid port/name stops startup. Although its diagnostic result retains the built-in maps for inspection, the exporter does not continue with that fallback.

#### External-rule file

With `behavior.rules_config` unset, no external rules are loaded and the built-in rules remain. A configured file that is missing, unreadable, empty, malformed, contains unknown fields or multiple YAML documents, or violates the external-rule schema stops startup; it is not ignored.

#### Custom threat list

An enabled custom list requires a non-empty path. An enabled or explicitly supplied non-empty `customlist.path` must already name a stable regular file containing at least one valid IP address at startup. A missing path, directory, special file, malformed or empty feed, or NUL-containing path is rejected. Later refreshes retain the existing atomic publication and last-good-on-failure contract.

#### Host interfaces

`host.interfaces` uses the default interface selection: enabling host threat matching without explicitly setting the flag selects `bgp-nic`. An explicitly empty list is still an error, including while matching is disabled. Every selected component must be non-empty, contain no NUL byte, and resolve by exact name through the host network-interface API. A configured list is validated even when host threat matching is disabled. Any failed lookup stops startup and can never turn into an empty filter that scans every interface.

#### Log destination

When file logging is enabled, `log.file.path` must be non-empty, contain no NUL byte, and open as a regular create-or-append destination with mode `0644`. The exporter retains that validated open handle for logging and runtime level changes. Failure stops startup instead of silently continuing with stdout-only logging. When file logging is disabled, the inactive path is not opened.

### Telemetry path

The telemetry path defaults to `/metrics`. A configured value must be one literal, directly reachable URL path: it begins with `/`, is not `/`, has no trailing slash, query, fragment, wildcard, escape transformation, or path-cleaning requirement, and does not equal the reserved `/debug/log-level` path. Invalid patterns are rejected without an `http.ServeMux` panic.

## Runtime log-level endpoint

`-web.debug-log-level.enable` defaults to `true`. When it is `false`, `/debug/log-level` is not registered at all and both reads and writes receive `404 Not Found`. The telemetry-path validator continues to reserve that exact path even when the endpoint is disabled.

When enabled, the exact method contract is:

| Request | Result | Mutation |
| --- | --- | --- |
| `GET /debug/log-level` with no `level` query key | `200`, body `current log level: <canonical>\n` | None |
| `GET` with any `level` key, including empty or repeated values | `400` | None |
| `POST` with exactly one non-blank valid `level` value | `200`, body `log level set to <canonical>\n` | Sets the level once |
| `POST` with a missing, blank, repeated, or invalid `level` value | `400` | None |
| Any other method, including `HEAD` and `OPTIONS` | `405`, `Allow: GET, POST` | None |

Valid runtime values are the same trimmed, case-insensitive `debug`, `info`, `warn`, `notice`, and `error` set accepted at startup; `notice` is reported and stored canonically as `warn`. Unrelated query keys do not mutate state and do not substitute for `level`. Responses use `text/plain; charset=utf-8`. Concurrent GET, valid POST, and rejected requests preserve the same method and mutation rules without racing the logging state.

## HTTP resource limits

The production HTTP server has these fixed settings:

| Control | Value | Contract |
| --- | ---: | --- |
| `ReadHeaderTimeout` | `10s` | Bounds receipt of request headers. |
| `IdleTimeout` | `2m` | Bounds idle keep-alive connections. |
| `MaxHeaderBytes` | `32768` (32 KiB) | Configures the maximum request-header size. |
| Concurrent metrics requests | `4` | Four scrapes may gather concurrently. A request arriving while all four slots are occupied receives `503 Service Unavailable`; a completed request releases its slot. |
| Graceful-shutdown deadline | `10s` | Stops accepting new connections and gives in-flight handlers this bounded drain window. |
| `WriteTimeout` | `0` (disabled) | A legitimate large or slow Prometheus response is not cut off by a short global write deadline. |

The in-flight metrics limit bounds concurrent collection work while the disabled write timeout preserves normal Prometheus scraping. A metrics request that declares a body or transfer encoding is rejected with `400 Bad Request` and connection close before it can occupy a collection slot. Large responses are tested through the production server, including incremental flushes. Header, idle, concurrency, and shutdown controls provide the bounds instead of a response deadline that could truncate a valid scrape.

### Shutdown behavior

On `SIGINT` or `SIGTERM`, the server performs graceful shutdown. Requests that finish inside the deadline drain normally. If the deadline expires, the server forcibly closes active connections, cancels their request contexts, waits for the serving goroutine to exit, and returns the deadline error. Listener failures, unexpected server termination, and forced-shutdown failures remain visible runtime errors.

## Compatibility boundary

The v2.0.0 release defines **148 `oie_*` metric families**, **51 runtime flags** and **82 alert definitions** in one group. The default alert policy enables 33 definitions and includes ten shared recording rules. See [the compatibility baseline](COMPATIBILITY_BASELINE.md) for the published v1.2.0 comparison.

The runtime log-level control is recorded in its dedicated CLI fixture:

```text
web.debug-log-level.enable|"true"|Enable the runtime log-level debug endpoint
```

The supported feeds remain Spamhaus, Tor Exit, Tor Relay, Emerging Threats, and Custom List. Runtime-configuration regression fixtures describe their original development checkpoint; their 136-family and 78-alert inventories are historical test inputs, not the shipped release inventory.

Every Compatibility baseline through Prometheus alert validation golden asset remains byte-for-byte unchanged. Later inventory, alert-policy and optional retype additions have separate executable coverage.

## Acceptance guarantees

The configuration tests enforce these guarantees:

1. An invalid explicit value cannot be clamped, defaulted, ignored, or broadened into a running configuration.
2. Missing or malformed configured YAML stops startup, while an omitted optional file retains documented built-ins.
3. A missing explicit host-interface flag uses the default `bgp-nic` selection; a missing selected interface still fails closed and cannot broaden matching to all interfaces.
4. A GET request cannot mutate exporter state; invalid and unsupported requests cannot mutate it either.
5. Disabling the debug endpoint removes it from the mux rather than leaving a read-only or discoverable handler.
6. Metrics concurrency, header receipt, idle connections, and shutdown are bounded without a write timeout that truncates valid scrapes.
7. Public interface changes are recorded in the compatibility fixtures, including the runtime log-level control and opt-in volume-retype flag.
