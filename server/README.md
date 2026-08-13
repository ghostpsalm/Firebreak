# The collector

Where Firebreak's opt-in usage ping goes. See `../TELEMETRY.md` for what is
sent and why; this file is about running the thing that receives it.

```
        client                     Oracle Always Free VM
   ┌──────────────┐        ┌──────────────────────────────────┐
   │  firebreak   │  TLS   │  nginx :443  (certbot/LE)        │
   │  --telemetry │ ─────► │    ├─ /v1/*    → 127.0.0.1:8787  │
   └──────────────┘        │    └─ (later)  → 127.0.0.1:8788  │
                           │  firebreak-receiver (loopback)   │
                           │    └─ SQLite /var/lib/…          │
                           └──────────────────────────────────┘
```

Two pieces:

- **`receiver/`** — the service. Three TypeScript files on Deno, and
  **no third-party dependency at all** in what gets deployed: only local
  modules and Deno's built-in `node:sqlite`. It takes one small POST per
  install per day.
- **`terraform/`** — the host, the network, TLS and the systemd unit.

nginx is there so this box can carry more than one thing later. Adding a
second service is a loopback port and a `location` block — the template has
the comment marking where.

**Why Deno and not a compiled binary.** There is no build step: deploying a
change is a file copy and a restart, which is what makes this box cheap to
own. The runtime also enforces the security boundary itself — see the
permission flags below — which a compiled binary cannot do for itself. The
cost is about 70 MB resident instead of about 5, which on a 1 GB box is a
price worth paying and on this workload buys nothing back in speed.

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

1. **Point DNS at the IP** the apply printed. A timer keeps retrying
   issuance every ten minutes until the name resolves, so doing this after
   the apply is fine.
2. **Check it answers**: `curl https://your.domain/healthz` → `ok`.
3. **Point the client at it**: set `ENDPOINT` in `src/telemetry.rs` to
   `https://your.domain/v1/ping` and cut a release. Until that constant is
   set, no build sends anything and no consent prompt is ever shown.

The first apply takes two to three minutes — mostly `apt` and installing
Deno. There is nothing to compile.

**If DNS is not pointing here yet**, that is fine and expected: a
`firebreak-certbot.timer` retries issuance every ten minutes and stops the
moment a certificate exists. Renewal after that is certbot's own packaged
timer. Until the certificate arrives the site answers on port 80 only; once
it does, port 80 becomes a 308 to https and only the ACME challenge is served
in plaintext.

### Redeploying just the service

Editing any of `main.ts`, `ping.ts` or `db.ts` changes the trigger hash, so a
plain `terraform apply` copies the new files up and restarts. To force it:

```bash
terraform apply -replace=null_resource.receiver
```

The `*_test.ts` files are deliberately **not** deployed — the box has no
business holding a test suite, and they are the only files here with a
third-party import.

### Working on the receiver

```bash
cd server/receiver
deno task check     # fmt, lint, typecheck, test
deno task dev       # run it locally on 127.0.0.1:8787
```

`./scripts/gate.sh` runs the same checks, and skips them with a loud warning
if Deno is not installed so a Windows contributor working on the client is
not blocked by the collector's toolchain. CI installs Deno, so they are never
skipped there.

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
| `FB_HOST` / `FB_PORT` | `127.0.0.1` / `8787` | Loopback on purpose — nginx is the only thing that should reach it. |
| `FB_DB` | `/var/lib/firebreak-receiver/telemetry.db` | |
| `FB_RETENTION_DAYS` | `400` | Swept at startup and daily. |
| `FB_RATE_PER_HOUR` | `240` | Per `/24` or `/48`. Generous because one network can hold a lot of machines that all boot at nine. |

## What protects it

- **The receiver binds loopback.** It is not reachable from off-box at all.
  The VCN security list opens 22, 80 and 443 and nothing else, and the
  instance's own iptables is opened to match — both are needed, and
  forgetting the second is the classic reason ACME times out.
- **The runtime enforces the boundary, not just the config.** The service is
  started with `--no-remote`, `--allow-net` scoped to its own listening
  address, `--allow-read`/`--allow-write` scoped to the database directory,
  and `--allow-env` naming five variables. No subprocess, no FFI, no wider
  filesystem, and no ability to fetch code at runtime. Those flags in
  `firebreak-receiver.service` are the thing to read first, and they fail
  closed and loudly: pointed at a path outside its grant the process exits
  with `NotCapable` rather than opening the file.
- **TLS only.** certbot obtains and renews a Let's Encrypt certificate; port
  80 carries nothing but the ACME challenge and a 308 to https, and HSTS is
  set. The client will not talk to a non-`https://` endpoint in the first
  place — WinHTTP is given `WINHTTP_FLAG_SECURE` on 443, curl is pinned with
  `--proto =https --proto-redir =https`, and an endpoint that does not start
  `https://` disables the feature outright.
- **Everything is bounded**: body size at both nginx and the receiver, a
  per-network rate limit, and the listener's own concurrency. The body cap is
  applied to the *stream* and not merely to the declared `Content-Length`,
  because a header is a claim and a chunked request makes no claim at all.
- **Unknown JSON fields are a rejection**, not a stored curiosity. The
  collector cannot be turned into somewhere to put arbitrary data.
- **The daily-uniqueness rule is enforced in the database**, not trusted to
  the client.
- **`X-Forwarded-For` is read from the end, not the start.** nginx's
  `$proxy_add_x_forwarded_for` appends the real peer to whatever the client
  sent, so the last entry is the only trustworthy one; taking the first — the
  usual advice for an edge server — would let any client choose what gets
  recorded about it.
- **The unit is confined** (`ProtectSystem=strict`, `NoNewPrivileges`, a
  syscall filter, no home, no shell) because it parses input from the
  internet.
- **No access log.** `access_log off` in the site, so the log next to the
  database cannot hold the addresses the database is careful not to.

## Tearing it down

```bash
terraform destroy
```

Takes the database with it. Copy it down first if you want to keep it.
