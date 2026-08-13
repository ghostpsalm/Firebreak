# What Firebreak sends, and when

Firebreak runs as administrator or root, over your firewall. A tool in that
position that quietly reports home has earned any suspicion it gets. So this
document is the standing, complete statement of what leaves your machine —
and the tool itself will show you the actual bytes on request:

```
firebreak --telemetry preview
```

That prints the payload from the same code that sends it, so it cannot drift
away from the truth. Nothing here asks you to take the source's word for it.

## The short version

- **Off until you say otherwise.** Nothing is sent, and no identity is even
  generated, until you answer yes.
- **One ping a day at most**, whatever you do with the tool.
- **Nothing about your firewall is in it.** No rule names, addresses, ports,
  hostnames, usernames, paths or serial numbers.
- **It can be turned off permanently**, from the window, the command line, or
  the environment.

## What is sent

The whole payload, and there is nothing else:

| Field | Example | Why |
|---|---|---|
| `schema` | `1` | Payload version. |
| `install_id` | `9f3c…` (32 hex) | Random, **replaced every 90 days**. Distinguishes "100 people ran it once" from "5 people ran it 20 times". |
| `app_version` | `0.7.81` | Which release is in the field, so old ones can be supported or retired. |
| `os` | `linux` | `windows` or `linux`. |
| `os_name` | `Fedora Linux` | Distro, or Windows family. |
| `os_version` | `44` | Release, e.g. `44`, or `26100 (24H2)`. |
| `arch` | `x86_64` | Whether ARM builds are worth producing. |
| `backend` | `firewalld` | Which firewall is in charge: `wfp`, `ufw`, `firewalld`, `nftables`, `none`. This is the single most useful field. |
| `board_vendor` | `ASUSTeK` | Motherboard or system manufacturer, from DMI. Vendor **only**. |
| `virtual_machine` | `false` | Whether the DMI vendor is a hypervisor. |
| `age` | `31-90` | How long telemetry has been on here, as a band. |
| `runs` | `6-20` | How many runs since then, as a band. |
| `features` | `["apply","collect"]` | Which of eight named features have ever been used. |

`age` and `runs` are bands rather than numbers on purpose. The install ID
rotates, and an exact "day 412, run 1,043" would let a new ID be stitched back
onto the old one, which would defeat the rotation.

`features` is a closed vocabulary of exactly eight values — `apply`,
`collect`, `desktop`, `enable_only`, `headless`, `review`, `support`,
`update`. There is no mechanism for recording an arbitrary string.

## What is never sent

- Hostnames, usernames, domain names, file paths
- **Anything read out of your firewall** — no rule names, no addresses, no
  ports, no process names, no counters, no evidence of any kind
- Serial numbers of any kind. The code reads
  `/sys/class/dmi/id/board_vendor`; `product_serial` and `board_serial` sit
  in the same directory and are deliberately never touched
- Any content of an audit bundle, or anything about a machine you reviewed

## About your IP address

The payload contains no address. But the server that receives it sees one,
exactly as any website you visit does — that is how the internet works, and a
claim to the contrary would be a lie.

What happens to it:

- It is **truncated before it is stored**: IPv4 to a `/24`
  (`203.0.113.47` → `203.0.113.0`), IPv6 to a `/48`.
- The full address is **never written anywhere** — not to the database, and
  not to a log. The reverse proxy's access log is switched off for exactly
  this reason, so the log beside the database cannot undo the care taken in
  it.
- Rows are **deleted after 400 days** by default.

## Turning it on and off

| | |
|---|---|
| `firebreak --telemetry status` | What is stored, and whether pings are on |
| `firebreak --telemetry preview` | Print the exact JSON that would be sent |
| `firebreak --telemetry on` | Turn pings on |
| `firebreak --telemetry off` | Turn pings off, and **erase** the stored install ID and run history |
| `firebreak --no-telemetry` | Skip the ping for one run, changing nothing |
| `FIREBREAK_NO_TELEMETRY=1` | Disable everywhere; no prompt is ever shown |

In the window it is under **About → Usage pings → Change…**.

Turning it off is not just a flag: the stored install ID, enrolment date and
run count are deleted, so there is nothing left on the machine to send later.

## How you are asked

On the first run of a build that has a collector configured, the window shows
one dialog listing the above and offering *No thanks* / *Yes, send pings*.
Until it is answered, nothing is sent. Closing it with Escape is not consent —
it is asked again next time.

A headless run (`--no-ui`, or a server over SSH) **cannot ask**, so it never
asks and never sends. Telemetry on a machine like that only ever happens
because someone ran `--telemetry on` there deliberately.

## Builds that cannot send anything

`ENDPOINT` in `src/telemetry.rs` is empty in the source repository, and empty
switches the entire feature off — no prompt, no stored state, no request. A
build made from a plain checkout is incapable of reporting anything, and
`--telemetry status` will tell you so.

## The receiving end

The collector is in this repository too, under `server/` — a small Rust
service behind Caddy on an Oracle Always Free host, storing to SQLite. It:

- accepts one payload shape and **rejects unknown fields outright**, so it
  cannot be used as a place to put arbitrary data;
- validates every field against a closed vocabulary or a length cap;
- enforces one row per install per day in the database, so a client that
  ignored its own interval could not inflate the numbers;
- truncates the address before storing, and logs only the truncated form.

See `server/README.md` for how it is deployed.
