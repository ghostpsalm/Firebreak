#![cfg_attr(windows, windows_subsystem = "windows")]

mod app_identity;
mod audit_control;
mod baseline_checks;
mod collect;
mod console;
mod default_policy;
mod desktop;
mod elevation;
mod event_query;
mod filter_map;
mod firewall_rules;
#[cfg(target_os = "linux")]
mod linux;
mod listeners;
mod model;
mod pipeline;
mod preview;
mod review;
mod scope;
mod secure_dir;
mod store;
mod support;
mod syspath;
mod telemetry;
mod theme;
mod time_util;
mod ui;
mod update;
mod winhttp;
mod winpriv;

use anyhow::{bail, Context, Result};

use store::Store;

struct Args {
    collect: Option<Option<std::path::PathBuf>>,
    enable_only: bool,
    no_ui: bool,
    dump_filters: bool,
    export_support: bool,
    ui_preview: bool,
    restore_audit: bool,
    reset: bool,
    update: bool,
    check_update: bool,
    install_desktop: bool,
    uninstall_desktop: bool,
    review: Option<std::path::PathBuf>,
    db_path: std::path::PathBuf,
    /// `--telemetry <on|off|status|preview>`, when given.
    telemetry: Option<String>,
    /// `--no-telemetry`: suppress the ping for this run only, without
    /// changing the stored answer.
    no_telemetry: bool,
}

fn parse_args() -> Args {
    parse_args_from(std::env::args().skip(1))
}

fn parse_args_from(args_iter: impl Iterator<Item = String>) -> Args {
    let mut args = Args {
        collect: None,
        enable_only: false,
        no_ui: false,
        dump_filters: false,
        export_support: false,
        ui_preview: false,
        restore_audit: false,
        reset: false,
        update: false,
        check_update: false,
        install_desktop: false,
        uninstall_desktop: false,
        review: None,
        db_path: store::default_db_path(),
        telemetry: None,
        no_telemetry: false,
    };
    let mut it = args_iter.peekable();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--enable-only" => args.enable_only = true,
            "--collect" => {
                // optional path; default lands on the Desktop. Only consume
                // the next token as the path if it isn't itself a flag —
                // `--collect --enable-only` must leave --enable-only for the
                // loop, not silently swallow it.
                let path = it.peek().filter(|p| !p.starts_with("--")).is_some();
                args.collect = Some(if path {
                    it.next().map(Into::into)
                } else {
                    None
                });
            }
            "--no-ui" => args.no_ui = true,
            "--dump-filters" => args.dump_filters = true,
            "--export-support" => args.export_support = true,
            "--ui-preview" => args.ui_preview = true,
            "--restore-audit" => args.restore_audit = true,
            "--update" => args.update = true,
            "--check-update" => args.check_update = true,
            "--install-desktop" => args.install_desktop = true,
            "--uninstall-desktop" => args.uninstall_desktop = true,
            "--review" => match it.peek().filter(|p| !p.starts_with("--")) {
                Some(_) => args.review = it.next().map(Into::into),
                None => {
                    eprintln!("--review requires the path to a bundle (.zip)");
                    std::process::exit(2);
                }
            },
            "--reset" => args.reset = true,
            "--no-telemetry" => args.no_telemetry = true,
            "--telemetry" => match it.peek().filter(|p| !p.starts_with("--")) {
                Some(_) => args.telemetry = it.next(),
                None => {
                    eprintln!("--telemetry requires on, off, status or preview");
                    std::process::exit(2);
                }
            },
            "--db" => match it.peek().filter(|p| !p.starts_with("--")) {
                Some(_) => args.db_path = it.next().unwrap().into(),
                None => {
                    // covers both a missing value and a following flag
                    // (`--db --no-ui` must not treat "--no-ui" as a path)
                    eprintln!("--db requires a path argument");
                    std::process::exit(2);
                }
            },
            "--help" | "-h" => {
                println!(
                    "Firebreak — Observe first. Enforce with confidence.\n\
                     Firewall rule-usage auditor for Windows and Linux.\n\n\
                     USAGE:\n\
                     \x20 firebreak [OPTIONS]\n\n\
                     ON LINUX: runs as root and opens the same window as Windows;\n\
                     \x20 --no-ui prints the rule-usage report and exits instead.\n\
                     \x20 ufw       the kernel already counts every rule, so there is nothing\n\
                     \x20           to enable and no waiting period — the first run answers.\n\
                     \x20 firewalld its nftables table is owner-locked and carries no counters,\n\
                     \x20           so --enable-only installs Firebreak's own shadow counter\n\
                     \x20           table and --restore-audit removes it again. A plain run\n\
                     \x20           never instruments the host.\n\
                     \x20 nftables  reads each rule's own counter, where the ruleset has one.\n\
                     \x20           --enable-only adds counters to the rules that don't (the\n\
                     \x20           ruleset is backed up first and every edit verified);\n\
                     \x20           --restore-audit puts the ruleset back.\n\
                     \x20 --reset   clear collected totals and start counting over.\n\
                     \x20 --collect [path]  write a portable audit bundle (rules + the totals\n\
                     \x20                   counted so far) for review on another machine.\n\
                     \x20 --db      database path (default /var/lib/firebreak/firebreak.db)\n\
                     \x20 The remaining options below are Windows-only.\n\n\
                     ON WINDOWS:\n\
                     Run without arguments for the app: it boots to the rule table, offers an\n\
                     'Enable connection auditing' button on first run, and on later runs\n\
                     ingests new 5156/5157 events and correlates them to firewall rules.\n\
                     All options require elevation except --ui-preview and --help.\n\n\
                     COLLECTION:\n\
                     \x20 --collect [path]  export an offline audit bundle (rules + network\n\
                     \x20                   profiles + filtered Security events) as a .zip for\n\
                     \x20                   review on another machine. Default: the Desktop.\n\
                     \x20 --enable-only     enable connection auditing, snapshot the rule set,\n\
                     \x20                   and exit without opening the UI. Records the prior\n\
                     \x20                   audit state first so --restore-audit can undo it.\n\
                     \x20                   Use to start the collection clock on a host you'll\n\
                     \x20                   analyze later. Read-only apart from the audit policy\n\
                     \x20                   and Security log size.\n\
                     \x20 --restore-audit   restore the audit policy and Security log size\n\
                     \x20                   recorded before Firebreak first changed them.\n\
                     \x20                   Collected usage data is left untouched.\n\n\
                     ANALYSIS:\n\
                     \x20 --no-ui           ingest new events and print a text report to the\n\
                     \x20                   terminal instead of opening the UI. Never modifies\n\
                     \x20                   firewall rules.\n\
                     \x20 --reset           clear collected usage and the ingestion checkpoint;\n\
                     \x20                   the next run re-scans the whole Security log.\n\
                     \x20 --db <path>       database path\n\
                     \x20                   (default %ProgramData%\\firebreak\\firebreak.db)\n\n\
                     DIAGNOSTICS:\n\
                     \x20 --dump-filters    dump the live WFP filter table (filter id, name,\n\
                     \x20                   provider data) for verifying filter->rule mapping.\n\
                     \x20 --export-support  write a diagnostic bundle to the Desktop: audit\n\
                     \x20                   state, rules, filters, and an event attribution\n\
                     \x20                   probe. Review/redact before sharing.\n\
                     \x20 --ui-preview      open the UI with mock data (no elevation needed).\n\n\
                     REVIEW (both platforms):\n\
                     \x20 --review <path>   open an audit bundle collected elsewhere. Read-only:\n\
                     \x20                   it describes another machine, so nothing in that\n\
                     \x20                   window can change this host's firewall. Needs no\n\
                     \x20                   privileges. Add --no-ui for a text report instead.\n\n\
                     DESKTOP (Linux):\n\
                     \x20 --install-desktop install a desktop entry so Firebreak can be started\n\
                     \x20                   from the application menu. It asks for authorisation\n\
                     \x20                   at launch (pkexec) because the audit needs root.\n\
                     \x20                   Run it once, as root, from wherever the binary lives.\n\
                     \x20 --uninstall-desktop  remove that entry again.\n\n\
                     UPDATES (both platforms):\n\
                     \x20 --check-update    report whether a newer release is published.\n\
                     \x20 --update          download, verify and install the newest release.\n\
                     \x20                   The download is checked against the pinned signing\n\
                     \x20                   key and refused if it does not verify.\n\n\
                     TELEMETRY (both platforms, off until you say otherwise):\n\
                     \x20 Firebreak can send one anonymous ping a day so its author knows\n\
                     \x20 which systems to support. It is opt-in: nothing is sent until you\n\
                     \x20 answer yes, the window asks once, and a headless run never asks and\n\
                     \x20 never sends unless --telemetry on was run here.\n\
                     \x20 Sent:   OS and version, CPU architecture, firewall backend, board\n\
                     \x20         manufacturer, Firebreak's version, a rotating random install\n\
                     \x20         ID, and which features have been used.\n\
                     \x20 Never:  hostnames, usernames, rule names, addresses, ports, file\n\
                     \x20         paths, serial numbers, or anything read out of your firewall.\n\
                     \x20 Your IP is not in the message, but the server sees it as any website\n\
                     \x20 would; it is stored only as a coarse network prefix, never in full.\n\
                     \x20 --telemetry status   what is stored and whether pings are on\n\
                     \x20 --telemetry preview  print the exact JSON that would be sent\n\
                     \x20 --telemetry on|off   answer, or change the answer, at any time\n\
                     \x20 --no-telemetry       skip the ping for this run only\n\
                     \x20 Setting FIREBREAK_NO_TELEMETRY=1 disables it everywhere, and no\n\
                     \x20 prompt is ever shown.\n\n\
                     EXAMPLES:\n\
                     \x20 firebreak --enable-only      start collecting on a server, come back\n\
                     \x20                              in a few weeks\n\
                     \x20 firebreak --no-ui            quick text report over what's collected\n\
                     \x20 firebreak --restore-audit    put the host's audit config back as found\n\n\
                     Firewall rules are only ever modified from the UI (Apply, with a\n\
                     restorable policy backup written first) — no CLI option changes rules."
                );
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown argument: {other} (see --help)");
                std::process::exit(2);
            }
        }
    }
    args
}

fn main() -> Result<()> {
    // GUI-subsystem binary: reattach to the parent terminal so CLI flags
    // still print when run from a shell
    console::attach_parent_console();
    let args = parse_args();

    if args.ui_preview {
        return preview::run();
    }

    // Clear a leftover image from a prior self-update. Both platforms leave
    // the old binary alongside the new one, so both have to sweep it — doing
    // this only on Windows left a stale copy on every updated Linux host.
    update::cleanup_old();

    // Reviewing a bundle describes another machine, so it needs neither
    // this host's firewall nor root — and must not touch either. Handled
    // before every platform branch for exactly that reason.
    if let Some(path) = &args.review {
        mark(&args.db_path, telemetry::Feature::Review);
        let bundle = review::read(path).with_context(|| format!("reading {}", path.display()))?;
        let source = format!(
            "{} ({}) collected {}",
            bundle.manifest.hostname, bundle.manifest.os, bundle.manifest.collected_at
        );
        let result = review::to_result(bundle);
        // A bundle is often reviewed on a box with no display — a server
        // over SSH. Print it there rather than failing at the window.
        if args.no_ui {
            review::print_report(&result, &source);
            return Ok(());
        }
        return ui::run_review(result, source);
    }

    // Updating is independent of the firewall backend, and on a headless
    // server the About box is unreachable — so it gets a CLI path on both
    // platforms rather than being GUI-only.
    if args.check_update || args.update {
        mark(&args.db_path, telemetry::Feature::Update);
        return run_update(args.update);
    }

    // On Linux, take the counter-backend path when one of the supported
    // firewall managers is actually in charge. Otherwise fall through to the
    // shared flow, which still serves --ui-preview and reports honestly that
    // the Windows evidence sources are unavailable here.
    #[cfg(target_os = "linux")]
    {
        if !elevation::is_elevated() {
            bail!(
                "firebreak must run as root on Linux — the firewall's rule files, its packet \
                 counters and /proc process attribution are all root-only. Re-run with sudo, \
                 or use --ui-preview to look at the interface unprivileged.\nTo start it from \
                 the desktop instead, run `sudo firebreak --install-desktop` once."
            );
        }
        // Writes under /usr, so it belongs after the root check and before
        // anything that needs a firewall backend — installing a launcher is
        // useful on a host Firebreak cannot yet audit.
        if args.install_desktop {
            mark(&args.db_path, telemetry::Feature::Desktop);
            println!("{}", desktop::install()?);
            return Ok(());
        }
        if args.uninstall_desktop {
            println!("{}", desktop::uninstall()?);
            return Ok(());
        }
        if let Some(backend) = linux::detect()? {
            return run_linux(&args, backend);
        }
        eprintln!(
            "No supported Linux firewall backend is active (Firebreak supports ufw and \
             firewalld; raw nftables is not wired up yet)."
        );
    }

    run_windows(args)
}

/// Check for a newer release and, when asked, install it. The signature gate
/// lives in `update`, so an unverifiable download is refused here too.
fn run_update(install: bool) -> Result<()> {
    let release = update::check()?;
    println!("Running: {}", release.current);
    println!("Latest:  {}", release.latest);
    if !release.newer {
        println!("Already up to date.");
        return Ok(());
    }
    if !install {
        println!("A newer release is available. Run --update to install it.");
        return Ok(());
    }
    println!("Downloading and verifying {}…", update::ASSET);
    let path = update::download_and_install()?;
    println!(
        "Installed {} at {}. The previous binary is alongside it as {}.old.",
        release.latest,
        path.display(),
        update::ASSET
    );
    #[cfg(target_os = "linux")]
    println!(
        "The desktop entry now points at the new binary ({}).",
        desktop::DESKTOP_FILE
    );
    Ok(())
}

/// `--telemetry <on|off|status|preview>`.
///
/// `preview` goes through the same builder the sender uses, so what it
/// prints and what would actually be posted cannot drift apart. That is the
/// whole point of it existing: nobody should have to read this source, or
/// take its word, to find out what a tool running as root sends home.
fn run_telemetry(cmd: &str, db_path: &std::path::Path, backend: &str) -> Result<()> {
    let store = Store::open(db_path)?;
    match cmd {
        "on" => {
            telemetry::set_consent(&store, telemetry::Consent::Granted, chrono::Utc::now())?;
            println!("Telemetry is on — one anonymous ping a day, at most.");
            if !telemetry::configured() {
                println!(
                    "This build has no collector configured, so nothing will actually be sent."
                );
            }
            println!("See exactly what it sends:  firebreak --telemetry preview");
        }
        "off" => {
            telemetry::set_consent(&store, telemetry::Consent::Denied, chrono::Utc::now())?;
            println!(
                "Telemetry is off. The stored install ID and run history have been erased, \
                 so there is nothing left here to send."
            );
        }
        "status" => {
            for line in telemetry::status_lines(&store) {
                println!("{line}");
            }
        }
        "preview" => {
            println!(
                "This is the entire payload, built by the same code that sends it.\n\
                 It goes to {} and nowhere else.\n",
                if telemetry::configured() {
                    telemetry::ENDPOINT
                } else {
                    "(no collector configured in this build)"
                }
            );
            println!(
                "{}",
                serde_json::to_string_pretty(&telemetry::preview(&store, backend)?)?
            );
        }
        other => bail!("--telemetry takes on, off, status or preview (got {other:?})"),
    }
    Ok(())
}

/// Which feature this run's flags represent, if any. A run has one dominant
/// mode, so this is an ordered match rather than a set — the plain windowed
/// run, which is the common case, is deliberately not a "feature".
fn feature_for(args: &Args) -> Option<telemetry::Feature> {
    if args.collect.is_some() {
        Some(telemetry::Feature::Collect)
    } else if args.enable_only {
        Some(telemetry::Feature::EnableOnly)
    } else if args.export_support {
        Some(telemetry::Feature::Support)
    } else if args.no_ui {
        Some(telemetry::Feature::Headless)
    } else {
        None
    }
}

/// Count this run and post a ping if one is due, returning the in-flight
/// request. Bind the result to a named local for the rest of the run — it
/// waits on drop, so every early return gets a bounded chance to finish.
///
/// A store that will not open costs the ping, never the run.
fn start_ping(args: &Args, backend: &str) -> Option<telemetry::Ping> {
    let store = Store::open(&args.db_path).ok()?;
    if let Some(f) = feature_for(args) {
        telemetry::mark(&store, f);
    }
    telemetry::maybe_send(&store, backend, args.no_telemetry)
}

/// Note a feature as used, best effort.
///
/// Telemetry must never be able to fail a run, so a store that will not open
/// is simply not recorded. The `configured` check keeps a build with no
/// collector from opening the database at all.
fn mark(db_path: &std::path::Path, feature: telemetry::Feature) {
    if !telemetry::configured() {
        return;
    }
    if let Ok(store) = Store::open(db_path) {
        telemetry::mark(&store, feature);
    }
}

/// The Linux run. Deliberately not the Windows flow with substitutions: on
/// ufw there is no audit policy to enable, no event log to checkpoint and no
/// collection clock to start, because the kernel is already counting, so the
/// first run has a real answer. firewalld does need instrumenting, and there
/// the existing collection flags carry over exactly:
///
/// * `--enable-only` installs the shadow counter table and exits, i.e. starts
///   the clock — the same job it does on Windows.
/// * `--restore-audit` removes it again, leaving collected totals intact.
#[cfg(target_os = "linux")]
fn run_linux(args: &Args, backend: linux::Backend) -> Result<()> {
    // Declare the host's scope vocabulary before anything renders a rule.
    model::set_vocabulary(backend.scope_vocabulary());

    if let Some(cmd) = &args.telemetry {
        return run_telemetry(cmd, &args.db_path, backend.label());
    }
    let _ping = start_ping(args, backend.label());

    // Windows-only options must say so. Falling through to the window
    // instead would silently do something the user did not ask for.
    // --collect is supported on both platforms now, but they ship different
    // things: Windows hands over a Security log for the reviewer to replay,
    // Linux hands over the totals it has banked, because a kernel counter is
    // a gauge and there is no event stream to give.
    if let Some(path) = &args.collect {
        let out = path.clone().unwrap_or_else(|| {
            std::path::PathBuf::from(review::default_name(&pipeline::hostname()))
        });
        let written = review::export(&args.db_path, &out)?;
        println!("Audit bundle written to:\n  {}", written.display());
        println!(
            "Open it anywhere — Linux or Windows:  firebreak --review {}",
            written.display()
        );
        return Ok(());
    }

    for (requested, flag, why) in [
        (
            args.dump_filters,
            "--dump-filters",
            "there is no WFP filter table on Linux",
        ),
        (
            args.export_support,
            "--export-support",
            "the support bundle collects Windows audit state",
        ),
    ] {
        if requested {
            bail!("{flag} is not available on Linux — {why}");
        }
    }

    if args.enable_only {
        println!("{}", linux::enable_collection(backend, &args.db_path)?);
        return Ok(());
    }
    if args.restore_audit {
        println!("{}", linux::stop_collection(backend, &args.db_path)?);
        return Ok(());
    }

    let store = Store::open(&args.db_path)?;
    if args.reset {
        store.reset_counter_state()?;
        println!("Cleared collected rule usage. Counting restarts from the next run.");
        return Ok(());
    }
    if args.no_ui {
        let prior = store.load_counter_state()?;
        let (report, next) = linux::analyze(backend, &prior)?;
        store.save_counter_state(&next)?;
        print_linux_report(backend, &report);
        return Ok(());
    }

    // Default, as on Windows: boot straight to the window. The rule table,
    // filters, drawer and CSV export are the same ones — only the evidence
    // behind them differs.
    drop(store);
    ui::run_live(args.db_path.clone())
}

fn run_windows(args: Args) -> Result<()> {
    model::set_vocabulary(model::ScopeVocabulary::windows_profiles());

    if !elevation::is_elevated() {
        // the embedded manifest normally forces a UAC prompt at launch;
        // this is the fallback when the process was started some other way
        if elevation::relaunch_elevated() {
            return Ok(());
        }
        bail!(
            "firebreak must run elevated (audit policy, Security log and WFP access all \
             require it). The elevation prompt was declined or unavailable."
        );
    }

    if let Some(cmd) = &args.telemetry {
        return run_telemetry(cmd, &args.db_path, "wfp");
    }
    // On a Linux host with no supported backend this flow still runs, and
    // calling that "wfp" would be a lie in the data.
    let _ping = start_ping(&args, if cfg!(windows) { "wfp" } else { "none" });

    if args.dump_filters {
        return dump_filters();
    }
    if args.export_support {
        let path = support::default_path();
        support::export(&path)?;
        println!("Support bundle written to:\n  {}", path.display());
        println!("Review/redact if needed, then send it back for diagnosis.");
        return Ok(());
    }
    if let Some(path) = args.collect {
        let out = path.unwrap_or_else(collect::default_bundle_path);
        collect::collect(&out, &|s: &str| println!("{s}"))?;
        println!("Bundle written to:\n  {}", out.display());
        println!("Open it on your analysis machine: Settings -> Import Firebreak export...");
        return Ok(());
    }
    if args.restore_audit {
        let store = Store::open(&args.db_path)?;
        return restore_audit(&store);
    }
    if args.reset {
        pipeline::reset(&args.db_path)?;
        println!(
            "Cleared usage data and checkpoint. The next run re-scans the whole Security log."
        );
        return Ok(());
    }
    if args.enable_only {
        pipeline::enable_collection(&args.db_path, &|s: &str| println!("{s}"))?;
        println!(
            "--enable-only: auditing is enabled. Run firebreak again later to analyze.\n\
             Note: local audit policy can be overridden by Group Policy on refresh; \
             re-check with: auditpol /get /subcategory:{}",
            audit_control::FILTERING_PLATFORM_CONNECTION_GUID
        );
        return Ok(());
    }
    if args.no_ui {
        if !pipeline::audit_enabled()? {
            pipeline::enable_collection(&args.db_path, &|s: &str| println!("{s}"))?;
            println!(
                "Auditing was not enabled — collection starts now; there is no retroactive \
                 data. Run again later to analyze."
            );
            return Ok(());
        }
        let result = pipeline::analyze(&args.db_path, &|s: &str| println!("{s}"))?;
        println!(
            "Ingested {} events ({} unattributed to a rule).",
            result.ctx.events_processed, result.ctx.unmatched_events
        );
        return print_text_report(&result);
    }

    // default: boot straight to the window; audit detection / enablement /
    // analysis run on background workers inside the app
    ui::run_live(args.db_path)
}

/// Put the host's audit configuration back to what was recorded before
/// firebreak first changed it (S-06). Collected usage data is left untouched.
fn restore_audit(store: &Store) -> Result<()> {
    println!("{}", pipeline::restore_audit_state(store)?);
    Ok(())
}

fn dump_filters() -> Result<()> {
    let filters = filter_map::enumerate_filters()?;
    println!("filter_id\tname\tprovider_context_key\tprovider_data_utf16\tprovider_data_hex");
    for f in &filters {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            f.filter_id, f.name, f.provider_context_key, f.provider_data_utf16, f.provider_data_hex
        );
    }
    eprintln!(
        "{} filters. Cross-check a FilterRTID from a 5156 event against this list.",
        filters.len()
    );
    Ok(())
}

/// Text report for a counter-based backend. Unused, used and unmeasurable
/// are three separate sections on purpose: folding "we could not read this
/// rule's counter" into the zero-hit list would invite the user to delete a
/// rule Firebreak never actually observed.
#[cfg(target_os = "linux")]
fn print_linux_report(backend: linux::Backend, report: &linux::Report) {
    // The one line of the headless path no test executes: reading the host's
    // own files is exactly the host-dependence the `Sources` seam exists to
    // keep out of the tests. `the_system_sources_are_ufws_two_defaults_files`
    // pins what `system()` returns; everything below it is covered by
    // `linux_report_text`'s tests.
    print!(
        "{}",
        linux_report_text(backend, report, &linux::default_policy::Sources::system())
    );
}

/// As [`print_linux_report`], rendered to a string and reading the stance
/// from the supplied sources so the whole report can be asserted on without
/// depending on the host it runs on.
#[cfg(target_os = "linux")]
fn linux_report_text(
    backend: linux::Backend,
    report: &linux::Report,
    sources: &linux::default_policy::Sources,
) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let _ = writeln!(
        out,
        "Backend: {} — {}",
        backend.label(),
        backend.evidence_summary()
    );
    if backend.needs_instrumentation() {
        let _ = writeln!(
            out,
            "Collection: opt-in (--enable-only), removable (--restore-audit)"
        );
    }
    // The rules below are exceptions; this is the verdict in the gaps
    // between them, and without it a reader cannot tell whether a port with
    // no rule is closed or wide open.
    match linux::default_policy::read_from(backend, sources) {
        Some(d) => {
            let _ = writeln!(
                out,
                "Unmatched inbound: {} — {}",
                d.verdict.headline().to_lowercase(),
                d.detail
            );
        }
        None => {
            let _ = writeln!(
                out,
                "Unmatched inbound: could not be determined on this host"
            );
        }
    }

    let unused = report.unused();
    // A never-matched rule that still has something listening behind it is a
    // different conversation from one with nothing there: the first may just
    // be waiting for its first connection.
    let (idle, empty): (Vec<&&linux::RuleUsageRow>, Vec<&&linux::RuleUsageRow>) =
        unused.iter().partition(|r| !r.listening.is_empty());
    let _ = writeln!(
        out,
        "\n=== Never matched, nothing listening ({}) — strongest disable candidates ===",
        empty.len()
    );
    for row in &empty {
        let _ = writeln!(
            out,
            "  {}  [{} {}]",
            row.rule.display_name, row.rule.direction, row.rule.action
        );
    }

    if !idle.is_empty() {
        let _ = writeln!(
            out,
            "\n=== Never matched, but something is listening ({}) ===",
            idle.len()
        );
        let _ = writeln!(
            out,
            "(the port is open and a process is behind it — it may simply be idle)"
        );
        for row in &idle {
            let _ = writeln!(
                out,
                "  {}  <- {}",
                row.rule.display_name,
                row.listening.join(", ")
            );
        }
    }

    let mut used: Vec<_> = report
        .rows
        .iter()
        .filter(|r| r.hits.unwrap_or(0) > 0)
        .collect();
    used.sort_by_key(|r| std::cmp::Reverse(r.hits.unwrap_or(0)));
    let _ = writeln!(out, "\n=== Matched (most first) ===");
    for row in used {
        let behind = if row.listening.is_empty() {
            String::new()
        } else {
            format!("  <- {}", row.listening.join(", "))
        };
        let _ = writeln!(
            out,
            "  {:>12} packets  {}{behind}",
            row.hits.unwrap_or(0),
            row.rule.display_name
        );
    }

    if let Some(note) = &report.note {
        let _ = writeln!(out, "\nNote: {note}");
    }

    if !report.unmeasurable.is_empty() {
        let _ = writeln!(
            out,
            "\n=== Not measurable ({}) — active, but with no usable hit count ===",
            report.unmeasurable.len()
        );
        let _ = writeln!(
            out,
            "(these are NOT unused; Firebreak simply cannot count them)"
        );
        for (id, why) in &report.unmeasurable {
            let _ = writeln!(out, "  {id}\n      {why}");
        }
    }

    out
}

fn print_text_report(result: &pipeline::AnalysisResult) -> Result<()> {
    print!("{}", wfp_report_text(result));
    Ok(())
}

/// As [`print_text_report`], rendered to a string instead of printed, so the
/// whole report is assertable from any host — the Windows `--no-ui` path
/// cannot be executed on the machine this is built on.
///
/// Every rule section reads a row set with the synthetic catch-all row
/// filtered out. It is not a rule: `default_policy::row` sets
/// `enabled: "True"` with no usage, so it satisfied "enabled and never
/// matched" and the report invited the reader to disable the host's default
/// inbound stance (#21). The verdict itself is not lost — it is stated on its
/// own line, the way the Linux report states it.
fn wfp_report_text(result: &pipeline::AnalysisResult) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    // The rules below are exceptions; this is the verdict in the gaps
    // between them, and without it a reader cannot tell whether a listening
    // socket with no rule is closed or wide open.
    match &result.ctx.default_inbound {
        Some(d) => {
            let _ = writeln!(
                out,
                "Unmatched inbound: {} — {}",
                d.headline.to_lowercase(),
                d.detail
            );
        }
        None => {
            let _ = writeln!(
                out,
                "Unmatched inbound: could not be determined on this host"
            );
        }
    }

    // The boundary for every rule section here, present and future: rows a
    // reader can actually act on.
    let rules: Vec<&ui::RuleRow> = result
        .rows
        .iter()
        .filter(|r| !r.is_default_policy())
        .collect();
    let mut sorted = rules.clone();
    sorted.sort_by_key(|r| r.total_hits());

    let _ = writeln!(out, "\n=== Zero-hit enabled rules (disable candidates) ===");
    // `is_zero_hit` is the GUI's own predicate for this list: measured, never
    // matched, and something Firebreak can switch off. A rule nobody counted
    // is unknown rather than zero, and a WFP filter is not a rule.
    for r in sorted
        .iter()
        .filter(|r| r.is_zero_hit() && r.rule.is_enabled())
    {
        let _ = writeln!(
            out,
            "  {} [{}] {} {} — scope: {}",
            r.rule.display_name,
            r.rule.direction,
            r.rule.action,
            r.rule.profile,
            listeners::scope_summary(&r.rule)
        );
    }

    let _ = writeln!(out, "\n=== Used rules (most hits first) ===");
    for r in sorted.iter().rev() {
        if let Some(u) = r
            .usage
            .as_ref()
            .filter(|u| u.allow_count + u.block_count > 0)
        {
            let _ = writeln!(
                out,
                "  {:>8} allow / {:>6} block  {}  last {}  apps: {}{}",
                u.allow_count,
                u.block_count,
                r.rule.display_name,
                u.last_seen.as_deref().unwrap_or("-"),
                r.seen_apps.join(", "),
                if r.listening.is_empty() {
                    String::new()
                } else {
                    format!("  listening: {}", r.listening.join(", "))
                }
            );
        }
    }

    let _ = writeln!(out, "\n=== Baseline flags ===");
    for r in rules
        .iter()
        .filter(|r| !r.flags.is_empty() && r.rule.is_enabled())
    {
        for f in &r.flags {
            let _ = writeln!(
                out,
                "  [{}] {} — {}",
                f.title, r.rule.display_name, f.advice
            );
        }
    }

    if !result.unmatched.is_empty() {
        let _ = writeln!(out, "\n=== Unattributed events (top 20) ===");
        let _ = writeln!(
            out,
            "(traffic decided by a default/system WFP filter, not a firewall rule — \
             e.g. the default block policy)"
        );
        for u in result.unmatched.iter().take(20) {
            let _ = writeln!(
                out,
                "  {}: {} allow / {} block, apps: {}",
                u.filter_name,
                u.usage.allow_count,
                u.usage.block_count,
                u.usage
                    .apps
                    .iter()
                    .take(3)
                    .map(|(p, _)| p.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    if !result.listeners.is_empty() {
        let _ = writeln!(out, "\n=== Active listening sockets ===");
        let mut sorted: Vec<_> = result.listeners.iter().collect();
        sorted.sort_by_key(|l| (l.proto.clone(), l.local_port));
        for l in sorted {
            let _ = writeln!(
                out,
                "  {:<4} {:>21}  {} (pid {})",
                l.proto,
                format!("{}:{}", l.local_address, l.local_port),
                if l.process_name.is_empty() {
                    "?"
                } else {
                    &l.process_name
                },
                l.pid
            );
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::parse_args_from;

    fn parse(argv: &[&str]) -> super::Args {
        parse_args_from(argv.iter().map(|s| (*s).to_string()))
    }

    #[test]
    fn collect_without_path_defaults() {
        let a = parse(&["--collect"]);
        assert_eq!(a.collect, Some(None));
    }

    #[test]
    fn collect_with_path_takes_it() {
        let a = parse(&["--collect", r"C:\out.zip"]);
        assert_eq!(a.collect, Some(Some(r"C:\out.zip".into())));
    }

    #[test]
    fn collect_does_not_swallow_following_flag() {
        // regression for F2: `--collect --enable-only` must run both, not
        // silently drop --enable-only while peeking for a path
        let a = parse(&["--collect", "--enable-only"]);
        assert_eq!(a.collect, Some(None));
        assert!(a.enable_only);
    }

    #[test]
    fn db_takes_a_path() {
        let a = parse(&["--db", r"D:\fb.db"]);
        assert_eq!(a.db_path, std::path::PathBuf::from(r"D:\fb.db"));
    }

    /// The headless report, rendered as text instead of printed (#19).
    ///
    /// `--no-ui` read the host's default inbound stance from inside the
    /// printing function, where nothing executed it: deleting that read left
    /// the gate green while every headless report silently dropped the
    /// verdict that says whether a listening socket with no rule is exposed.
    /// It is the second site of the defect PR #18 closed in `linux::bridge`.
    ///
    /// These assert on the **whole** rendered report rather than a stance
    /// line alone, because a helper that only produces the line could still
    /// be dropped from the report with nothing failing — which is the actual
    /// defect.
    #[cfg(target_os = "linux")]
    mod linux_report {
        use crate::linux::{default_policy::Sources, Backend, Report, RuleUsageRow};

        /// A ufw defaults file at a path nothing else in the run touches.
        /// The seam exists precisely so no test reads the host's real one —
        /// a report whose content depends on the host it runs on is the bug
        /// this line of work is fixing.
        fn ufw_sources(tag: &str, body: &str) -> (std::path::PathBuf, Sources) {
            let dir = std::env::temp_dir().join(format!("fb-noui-{tag}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let file = dir.join("ufw.conf");
            std::fs::write(&file, body).unwrap();
            (
                dir,
                Sources {
                    ufw_defaults: vec![file],
                },
            )
        }

        fn row(name: &str, action: &str, hits: Option<i64>) -> RuleUsageRow {
            RuleUsageRow {
                listening: Vec::new(),
                hits,
                rule: crate::model::RuleInfo {
                    name: name.into(),
                    display_name: name.into(),
                    description: None,
                    enabled: "True".into(),
                    direction: "Inbound".into(),
                    action: action.into(),
                    profile: "Any".into(),
                    group: None,
                    program: None,
                    protocol: None,
                    local_port: None,
                    remote_port: None,
                    service: None,
                    remote_address: None,
                    policy_source: None,
                    policy_source_type: None,
                },
            }
        }

        fn one_rule_report() -> Report {
            Report {
                rows: vec![row("a", "Allow", Some(4))],
                note: None,
                unmeasurable: vec![],
            }
        }

        /// The stance comes from the sources handed in, and it lands in the
        /// report. Asserted as the exact text of the whole report so that
        /// neither the line nor its wording can go missing unnoticed.
        #[test]
        fn the_headless_report_reads_the_stance_through_the_supplied_sources() {
            let (dir, sources) = ufw_sources(
                "stance-drop",
                "# /etc/default/ufw\nIPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\n\
                 DEFAULT_OUTPUT_POLICY=\"ACCEPT\"\n",
            );

            let text = crate::linux_report_text(Backend::Ufw, &one_rule_report(), &sources);

            // The *output* policy in the same file is accept; reading the
            // wrong key would report this host as open.
            assert_eq!(
                text,
                concat!(
                    "Backend: ufw — iptables counters, always on — nothing to enable\n",
                    "Unmatched inbound: blocked — ufw's DEFAULT_INPUT_POLICY is DROP\n",
                    "\n=== Never matched, nothing listening (0) — strongest disable candidates ===\n",
                    "\n=== Matched (most first) ===\n",
                    "             4 packets  a\n",
                )
            );

            let _ = std::fs::remove_dir_all(&dir);
        }

        /// A defaults file that exists but names no input policy is
        /// unreadable, not a deny. Reporting a block that is not there tells
        /// someone an exposed port is shut — see CLAUDE.md, "The
        /// default-inbound row": never assumed, unreadable is unknown.
        #[test]
        fn an_unreadable_default_is_unknown_never_a_deny() {
            let (dir, sources) = ufw_sources(
                "stance-nokey",
                "IPV6=yes\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\n",
            );

            let text = crate::linux_report_text(Backend::Ufw, &one_rule_report(), &sources);

            assert!(
                text.contains("Unmatched inbound: could not be determined on this host"),
                "{text}"
            );
            for verdict in ["blocked", "rejected", "allowed"] {
                assert!(
                    !text.contains(verdict),
                    "unknown must never render as {verdict}:\n{text}"
                );
            }

            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// The Windows headless report (#21).
    ///
    /// The synthetic catch-all row is enabled and has no usage, so it
    /// satisfied the old "enabled and never matched" filter and `--no-ui`
    /// listed the host's default inbound stance as a disable candidate — the
    /// one place CLAUDE.md's exclusion was never applied. Asserted as the
    /// exact text of the whole report, because a stance line produced by a
    /// helper nothing checks could be dropped again with nothing failing.
    mod wfp_report {
        use crate::{model::RuleInfo, pipeline::AnalysisResult, ui};

        fn rule(name: &str, source_type: Option<&str>) -> RuleInfo {
            RuleInfo {
                name: name.into(),
                display_name: name.into(),
                description: None,
                enabled: "True".into(),
                direction: "Inbound".into(),
                action: "Allow".into(),
                profile: "Any".into(),
                group: None,
                program: None,
                protocol: Some("TCP".into()),
                local_port: Some("22".into()),
                remote_port: None,
                service: None,
                remote_address: None,
                policy_source: None,
                policy_source_type: source_type.map(str::to_string),
            }
        }

        /// An enabled rule with no usage at all: measured (Windows ingests
        /// events, so "none" is an answer), never matched, editable.
        fn row(rule: RuleInfo) -> ui::RuleRow {
            ui::RuleRow {
                target_enabled: true,
                target_scopes: crate::model::ScopeSet::from_rule(
                    &rule,
                    &crate::model::vocabulary(),
                ),
                rule,
                usage: None,
                flags: Vec::new(),
                seen_apps: Vec::new(),
                listening: Vec::new(),
                reviewed: ui::ReviewState::No,
                hits_known: true,
            }
        }

        fn result(rows: Vec<ui::RuleRow>, stance: Option<ui::DefaultInbound>) -> AnalysisResult {
            AnalysisResult {
                rows,
                ctx: ui::AuditContext {
                    default_inbound: stance,
                    ..Default::default()
                },
                unmatched: Vec::new(),
                listeners: Vec::new(),
            }
        }

        /// Three zero-hit enabled rows reach the report; exactly one of them
        /// is a disable candidate. The synthetic verdict row cannot be
        /// disabled and is stated on its own line instead; the WFP filter is
        /// not a rule Firebreak can touch. The row that *is* a candidate
        /// still appears, so the filter has not simply emptied the list.
        #[test]
        fn the_default_policy_row_is_not_a_disable_candidate() {
            let synthetic = crate::default_policy::row(
                crate::default_policy::Verdict::Drop,
                "Domain,Private,Public",
                "Domain: DefaultInboundAction is Block",
                "everything else".into(),
            );
            let res = result(
                vec![
                    row(rule("ssh", None)),
                    row(rule("some-wfp-filter", Some(RuleInfo::SOURCE_TYPE_WFP))),
                    synthetic,
                ],
                Some(ui::DefaultInbound {
                    headline: "Blocked".into(),
                    socket_note: "no rule — unsolicited inbound blocked".into(),
                    source: "Windows Firewall profiles".into(),
                    detail: "Domain: DefaultInboundAction is Block".into(),
                }),
            );

            assert_eq!(
                crate::wfp_report_text(&res),
                concat!(
                    "Unmatched inbound: blocked — Domain: DefaultInboundAction is Block\n",
                    "\n=== Zero-hit enabled rules (disable candidates) ===\n",
                    "  ssh [Inbound] Allow Any — scope: TCP 22\n",
                    "\n=== Used rules (most hits first) ===\n",
                    "\n=== Baseline flags ===\n",
                )
            );
        }

        /// A host whose profiles could not be read is reported as unknown,
        /// never as a deny (CLAUDE.md, "The default-inbound row"). Claiming a
        /// block that is not there tells someone an exposed port is shut.
        #[test]
        fn an_unreadable_stance_is_unknown_never_a_deny() {
            let text = crate::wfp_report_text(&result(vec![row(rule("ssh", None))], None));

            assert_eq!(
                text,
                concat!(
                    "Unmatched inbound: could not be determined on this host\n",
                    "\n=== Zero-hit enabled rules (disable candidates) ===\n",
                    "  ssh [Inbound] Allow Any — scope: TCP 22\n",
                    "\n=== Used rules (most hits first) ===\n",
                    "\n=== Baseline flags ===\n",
                )
            );
        }
    }
}
