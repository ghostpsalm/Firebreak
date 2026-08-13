# The collector

Where Firebreak's opt-in usage ping goes. See `../TELEMETRY.md` for what is
sent and why; this file is about running the thing that receives it.

```
        client                     Oracle Always Free VM
   ┌──────────────┐        ┌──────────────────────────────────┐
   │  firebreak   │  TLS   │  Caddy :443                      │
   │  --telemetry │ ─────► │    ├─ /v1/*    → 127.0.0.1:8787  │
   └──────────────┘        │    └─ (later)  → 127.0.0.1:8788  │
                           │  firebreak-receiver (loopback)   │
                           │    └─ SQLite /var/lib/…          │
                           └──────────────────────────────────┘
```

Two pieces:

- **`receiver/`** — the service. Rust, three dependencies, no async runtime,
  no framework. It takes one small POST per install per day; a threaded
  listener is the right size for that, and a short dependency list is worth
  having on a box exposed to the internet.
- **`terraform/`** — the host, the network, TLS and the systemd unit.

Caddy is there so this box can carry more than one thing later. Adding a
second service is a loopback port and a `handle` block in the Caddyfile — the
template has the comment marking where.

## What it costs

Nothing. Everything provisioned is inside Oracle's Always Free allowance:
one `VM.Standard.E2.1.Micro` (1 OCPU, 1 GB), a 50 GB boot volume out of the
200 GB allowance, and the 10 TB/month of egress nobody will come close to.

A ping is a few hundred bytes once a day per install. Ten thousand installs
is under a megabyte a week.

## Deploying

You need: an Oracle Cloud account, an API signing key, an SSH key, and a
domain you can add a record to.

```bash
cd server/terraform
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars          # auth, domain, SSH key

terraform init
terraform apply
```

Then read the `next_steps` output. The order that matters:

1. **Point DNS at the IP** the apply printed. Caddy keeps retrying the
   certificate until the name resolves, so doing this after the apply is
   fine.
2. **Check it answers**: `curl https://your.domain/healthz` → `ok`.
3. **Point the client at it**: set `ENDPOINT` in `src/telemetry.rs` to
   `https://your.domain/v1/ping` and cut a release. Until that constant is
   set, no build sends anything and no consent prompt is ever shown.

The first apply takes about five to ten minutes: the receiver is built from
source on the box, which is why cloud-init adds swap — linking bundled SQLite
on a 1 GB machine without it gets killed by the OOM reaper.

### Redeploying just the service

Editing anything under `receiver/src/` changes the trigger hash, so a plain
`terraform apply` rebuilds and restarts the service without touching the host.
To force it:

```bash
terraform apply -replace=null_resource.receiver
```

### If the ARM shape is wanted

`VM.Standard.A1.Flex` is a far better machine and also free, but free-tier
capacity for it is frequently exhausted. Set `instance_shape`, `shape_ocpus`
and `shape_memory_gb` in `terraform.tfvars`, and expect to retry, varying
`availability_domain_index`, until one is granted.

## Looking at the data

```bash
ssh ubuntu@<ip> 'sudo firebreak-telemetry-summary'
```

Installs per day, platforms, and feature use. For anything else, the whole
dataset is one SQLite file — copy it down and query it locally:

```bash
ssh ubuntu@<ip> 'sudo cat /var/lib/firebreak-receiver/telemetry.db' > telemetry.db
sqlite3 telemetry.db 'SELECT backend, COUNT(DISTINCT install_id) FROM ping GROUP BY backend;'
```

(`sudo cat` rather than `scp` because the file is owned by the service user.
For a consistent copy under load, `sudo sqlite3 … ".backup /tmp/t.db"` first —
though at this volume there is no load to speak of.)

Live view:

```bash
ssh ubuntu@<ip> 'sudo journalctl -u firebreak-receiver -f'
```

The log prints the truncated network, never a full address.

## Configuration

The service reads four environment variables, set by the systemd unit that
Terraform renders:

| Variable | Default | |
|---|---|---|
| `FB_BIND` | `127.0.0.1:8787` | Loopback on purpose — Caddy is the only thing that should reach it. |
| `FB_DB` | `/var/lib/firebreak-receiver/telemetry.db` | |
| `FB_RETENTION_DAYS` | `400` | Swept at startup and daily. |
| `FB_RATE_PER_HOUR` | `240` | Per `/24` or `/48`. Generous because one network can hold a lot of machines that all boot at nine. |

## What protects it

- **The receiver binds loopback.** It is not reachable from off-box at all.
  The VCN security list opens 22, 80 and 443 and nothing else, and the
  instance's own iptables is opened to match — both are needed, and
  forgetting the second is the classic reason ACME times out.
- **TLS only.** Caddy gets and renews a Let's Encrypt certificate by itself;
  port 80 carries nothing but the ACME challenge and a 308 to https, and HSTS
  is set. The client will not talk to a non-`https://` endpoint in the first
  place — WinHTTP is given `WINHTTP_FLAG_SECURE` on 443, curl is pinned with
  `--proto =https --proto-redir =https`, and an endpoint that does not start
  `https://` disables the feature outright.
- **Everything is bounded**: connection count, header size, body size, socket
  timeouts and a per-network rate limit. A bad day costs a refusal. The head
  limit is applied *through* the reader rather than checked afterwards —
  `read_line` on its own will happily buffer megabytes looking for a newline
  that never comes, and `a_header_line_with_no_newline_is_refused_not_buffered`
  is the regression test for exactly that.
- **Unknown JSON fields are a rejection**, not a stored curiosity. The
  collector cannot be turned into somewhere to put arbitrary data.
- **The daily-uniqueness rule is enforced in the database**, not trusted to
  the client.
- **`X-Forwarded-For` is read from the end, not the start.** Caddy appends the
  real peer to whatever the client sent, so the last entry is the only
  trustworthy one; taking the first — the usual advice for an edge server —
  would let any client choose what gets recorded about it.
- **The unit is confined** (`ProtectSystem=strict`, `NoNewPrivileges`, a
  syscall filter, no home, no shell) because it parses input from the
  internet.
- **No access log.** Caddy is set to errors only, so the log next to the
  database cannot hold the addresses the database is careful not to.

## Tearing it down

```bash
terraform destroy
```

Takes the database with it. Copy it down first if you want to keep it.
