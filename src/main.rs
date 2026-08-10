#![cfg_attr(windows, windows_subsystem = "windows")]

mod app_identity;
mod audit_control;
mod baseline_checks;
mod collect;
mod console;
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
mod scope;
mod secure_dir;
mod store;
mod support;
mod syspath;
mod theme;
mod time_util;
mod ui;
mod update;
mod winhttp;
mod winpriv;

use anyhow::{bail, Result};

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
    db_path: std::path::PathBuf,
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
        db_path: store::default_db_path(),
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
            "--reset" => args.reset = true,
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
                     ON LINUX: runs as root, prints a rule-usage report and exits.\n\
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
                     UPDATES (both platforms):\n\
                     \x20 --check-update    report whether a newer release is published.\n\
                     \x20 --update          download, verify and install the newest release.\n\
                     \x20                   The download is checked against the pinned signing\n\
                     \x20                   key and refused if it does not verify.\n\n\
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

    // Updating is independent of the firewall backend, and on a headless
    // server the About box is unreachable — so it gets a CLI path on both
    // platforms rather than being GUI-only.
    if args.check_update || args.update {
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
                 or use --ui-preview to look at the interface unprivileged."
            );
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
    Ok(())
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

    // Windows-only options must say so. Falling through to the window
    // instead would silently do something the user did not ask for.
    for (requested, flag, why) in [
        (
            args.collect.is_some(),
            "--collect",
            "offline bundles carry a Windows .evtx, which has no Linux equivalent",
        ),
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
    println!(
        "Backend: {} — {}",
        backend.label(),
        backend.evidence_summary()
    );
    if backend.needs_instrumentation() {
        println!("Collection: opt-in (--enable-only), removable (--restore-audit)");
    }

    let unused = report.unused();
    // A never-matched rule that still has something listening behind it is a
    // different conversation from one with nothing there: the first may just
    // be waiting for its first connection.
    let (idle, empty): (Vec<&&linux::RuleUsageRow>, Vec<&&linux::RuleUsageRow>) =
        unused.iter().partition(|r| !r.listening.is_empty());
    println!(
        "\n=== Never matched, nothing listening ({}) — strongest disable candidates ===",
        empty.len()
    );
    for row in &empty {
        println!(
            "  {}  [{} {}]",
            row.rule.display_name, row.rule.direction, row.rule.action
        );
    }

    if !idle.is_empty() {
        println!(
            "\n=== Never matched, but something is listening ({}) ===",
            idle.len()
        );
        println!("(the port is open and a process is behind it — it may simply be idle)");
        for row in &idle {
            println!(
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
    println!("\n=== Matched (most first) ===");
    for row in used {
        let behind = if row.listening.is_empty() {
            String::new()
        } else {
            format!("  <- {}", row.listening.join(", "))
        };
        println!(
            "  {:>12} packets  {}{behind}",
            row.hits.unwrap_or(0),
            row.rule.display_name
        );
    }

    if let Some(note) = &report.note {
        println!("\nNote: {note}");
    }

    if !report.unmeasurable.is_empty() {
        println!(
            "\n=== Not measurable ({}) — active, but with no usable hit count ===",
            report.unmeasurable.len()
        );
        println!("(these are NOT unused; Firebreak simply cannot count them)");
        for (id, why) in &report.unmeasurable {
            println!("  {id}\n      {why}");
        }
    }
}

fn print_text_report(result: &pipeline::AnalysisResult) -> Result<()> {
    let rows = &result.rows;
    let mut sorted: Vec<&ui::RuleRow> = rows.iter().collect();
    sorted.sort_by_key(|r| r.total_hits());

    println!("\n=== Zero-hit enabled rules (disable candidates) ===");
    for r in sorted
        .iter()
        .filter(|r| r.rule.is_enabled() && r.total_hits() == 0)
    {
        println!(
            "  {} [{}] {} {} — scope: {}",
            r.rule.display_name,
            r.rule.direction,
            r.rule.action,
            r.rule.profile,
            listeners::scope_summary(&r.rule)
        );
    }

    println!("\n=== Used rules (most hits first) ===");
    for r in sorted.iter().rev() {
        if let Some(u) = r
            .usage
            .as_ref()
            .filter(|u| u.allow_count + u.block_count > 0)
        {
            println!(
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

    println!("\n=== Baseline flags ===");
    for r in rows
        .iter()
        .filter(|r| !r.flags.is_empty() && r.rule.is_enabled())
    {
        for f in &r.flags {
            println!("  [{}] {} — {}", f.title, r.rule.display_name, f.advice);
        }
    }

    if !result.unmatched.is_empty() {
        println!("\n=== Unattributed events (top 20) ===");
        println!(
            "(traffic decided by a default/system WFP filter, not a firewall rule — \
             e.g. the default block policy)"
        );
        for u in result.unmatched.iter().take(20) {
            println!(
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
        println!("\n=== Active listening sockets ===");
        let mut sorted: Vec<_> = result.listeners.iter().collect();
        sorted.sort_by_key(|l| (l.proto.clone(), l.local_port));
        for l in sorted {
            println!(
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
    Ok(())
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
}
