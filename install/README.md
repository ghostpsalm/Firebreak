# Installing Firebreak

Both platforms need administrator/root: every read in the evidence loop —
the Security log and audit policy on Windows, the firewall's rule files,
packet counters and `/proc/<pid>/exe` on Linux — is privileged. Firebreak
refuses to run unprivileged rather than silently reporting less than the
truth, so the installers set things up to elevate at launch instead of
degrading.

## Linux

```sh
curl -fsSL https://raw.githubusercontent.com/ghostpsalm/Firebreak/main/install/install.sh | sudo sh
```

Installs to `/usr/local/bin/firebreak` and adds a desktop entry, so Firebreak
appears in the application menu and asks for authorisation (pkexec) when
launched. `--prefix DIR`, `--no-desktop` and `--uninstall` are accepted.

## Windows

```powershell
irm https://raw.githubusercontent.com/ghostpsalm/Firebreak/main/install/install.ps1 | iex
```

Run it in an **elevated** PowerShell. Installs to
`%ProgramFiles%\Firebreak` and adds a Start Menu shortcut. `-Prefix`,
`-NoShortcut` and `-Uninstall` are accepted.

## What the scripts check

Firebreak's release assets are signed with minisign, and the same public key
is pinned inside the binary for self-update. Both installers verify the
signature **when a verifier is present** (`minisign` or `rsign`), and abort
on a mismatch.

When no verifier is installed they continue — over HTTPS from GitHub — but
say so plainly and print the SHA-256 to compare against the release page.
That is a weaker guarantee than the in-app updater gives, which fails closed
and never installs an unverified binary. Installing `minisign` first closes
the gap:

```sh
# Fedora
sudo dnf install minisign
# Debian/Ubuntu
sudo apt install minisign
```

## winget

`winget/` holds the manifests. They are **not** submitted automatically:
publishing to winget means opening a PR against `microsoft/winget-pkgs`, and
that is an owner's decision. Refresh them for a release first — winget
rejects a manifest whose hash does not match the published asset:

```sh
./install/winget/refresh.sh target/x86_64-pc-windows-gnu/release/firebreak.exe 0.7.79
winget validate --manifest install/winget    # on a Windows box
```
