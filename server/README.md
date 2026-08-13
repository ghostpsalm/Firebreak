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

### Continuous deployment

Once set up, a push to `main` that passes the gate deploys the collector by
itself — the file copy above becomes the fallback, not the routine.

Generate a key that exists only for this, and put its public half in
`terraform.tfvars`:

```bash
ssh-keygen -t ed25519 -f ci_deploy_key -N "" -C "firebreak CI deploy"
# deploy_public_key = "ssh-ed25519 AAAA... firebreak CI deploy"
terraform apply
terraform output ci_setup      # prints the three `gh secret set` commands
```

`ci_setup` gives you `OCI_HOST`, `OCI_DEPLOY_KEY` and `OCI_HOST_KEY` (plus an
optional `OCI_DOMAIN` for a public health check). Leave `deploy_public_key`
empty and no deploy account is created at all.

**What that key can do, and only that.** It is installed with
`command="/usr/local/bin/firebreak-deploy",restrict`, so presenting it runs
the deploy script and nothing else — no shell, no port forwarding, no pty, no
file reads, whatever the client asks for. A stolen secret buys the ability to
redeploy the collector, not a login on the box. Prove it yourself:

```bash
ssh -i ci_deploy_key deploy@<ip> whoami     # runs the deploy script, not whoami
```

The script is the interesting part, and it is deliberately suspicious of what
it is handed:

- **only three named members are extracted** from the archive, so a path
  traversal, an absolute path, a symlink or simply an extra file writes
  nothing anywhere;
- it **typechecks** (`deno check --no-remote`) before anything goes near the
  live directory;
- it **skips the restart entirely** when the code is byte-identical, so a
  push that only touched the client does not bounce a working service;
- it **health-checks after restarting and rolls back** if the collector does
  not come back, failing the pipeline. A green build over a collector that
  stopped answering is worse than a red one.

`OCI_HOST_KEY` is not optional — the workflow refuses to run without it
rather than falling back to `StrictHostKeyChecking=no`, which would let a
deploy be steered to another machine.

Deployment is scoped to the app on purpose. **Infrastructure is not applied
from CI**: `terraform apply` needs credentials that can create and destroy,
and remote state to go with them. That stays a decision made at a keyboard,
and state stays local.

If you want a human in the loop, add required reviewers to the `production`
environment in repo settings and the deploy waits for approval.

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

## When something goes wrong

One command gathers everything worth reading, so diagnosing a bad build is
not a memory test about which of six log files to open:

```bash
ssh ubuntu@<ip> 'sudo firebreak-collector-support' > support.txt
```

It reports cloud-init's status and output, the receiver's unit state and
journal, nginx status and error log, the certificate and certbot's log, what
is actually deployed and its checksums, listening sockets, iptables, disk,
memory, and the database's row count and date range — never its contents.
**Review before sharing**: nginx and certbot error logs can quote client
addresses, which nothing else on this host does.

Where each failure announces itself:

| Failure | Where you see it |
|---|---|
| Provisioning broke | `terraform apply` stops and prints the last 120 lines of `cloud-init-output.log`. It does **not** report success over a half-built box. |
| Deploy broke | The GitHub Actions run. If the restart failed, the deploy script quotes the service's last 40 journal lines into the CI log — the deploy key cannot open a shell to go and look afterwards, so if it did not print it, nobody would ever see it. |
| Certificate never arrived | `systemctl status firebreak-certbot.timer` and `/var/log/letsencrypt/`. Almost always DNS not resolving yet, or port 80 closed. |
| Collector misbehaving in service | `journalctl -u firebreak-receiver`. It logs each accepted ping, every rejection with its reason, retention sweeps, and any unhandled request failure with a stack. |

Logs are **persistent and capped** (`Storage=persistent`, 200 MB, one month):
a volatile journal is emptied by the reboot, which is very often the thing
you wanted to read about, and an uncapped one is a way to fill the disk.

Live view while you work:

```bash
ssh ubuntu@<ip> 'sudo journalctl -u firebreak-receiver -f'
```

The log prints the truncated network, never a full address.

To keep a record of the build itself, tee it — Terraform's output is
otherwise only ever on your terminal:

```bash
terraform apply 2>&1 | tee "apply-$(date +%Y%m%d-%H%M).log"
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
