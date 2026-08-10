//! Launching Firebreak from the desktop on Linux.
//!
//! An ELF binary has nowhere to carry an icon — there is no equivalent of
//! Windows' resource section, and a file manager will not run an executable
//! by double-click anyway. What Linux has instead is a *desktop entry*: a
//! `.desktop` file naming the command, and an icon installed into the icon
//! theme by name. This module writes both, plus a launcher between them.
//!
//! The launcher exists for one reason. Firebreak needs root — the rule
//! files, the packet counters and `/proc/<pid>/exe` for other users'
//! processes are all root-only, and the Linux path refuses to run
//! unprivileged rather than silently attributing less than it should. So
//! something has to elevate, and there are two ways to do it:
//!
//!  * the app re-execs itself under pkexec when it finds it is not root, or
//!  * the desktop entry starts an already-elevated process.
//!
//! Firebreak does the second. The first is what [`crate::elevation`]
//! deliberately refuses: a process that elevates *itself* asks the user to
//! trust a decision made after it was already running. Here the elevation
//! happens before Firebreak starts, through the desktop's own polkit agent,
//! and the binary keeps its "started as root or refuse" property untouched.
//!
//! The launcher forwards the display environment, which pkexec otherwise
//! strips, or the window has no compositor to open on. That does mean a root
//! process connecting to the user's display — the standing trade-off for any
//! GUI that needs privilege, and the same one Windows makes with a
//! `requireAdministrator` manifest.

#[cfg(target_os = "linux")]
use anyhow::{Context, Result};

// Where each piece goes. All under `/usr`, so installing needs the root the
// program already requires. Linux-only, like everything else here — a
// desktop entry is not a thing Windows has.
#[cfg(any(target_os = "linux", test))]
pub const DESKTOP_FILE: &str = "/usr/share/applications/firebreak.desktop";
#[cfg(any(target_os = "linux", test))]
pub const ICON_FILE: &str = "/usr/share/icons/hicolor/256x256/apps/firebreak.png";
#[cfg(any(target_os = "linux", test))]
pub const LAUNCHER: &str = "/usr/libexec/firebreak-launch";

/// The launcher script. `exec`s in place so the desktop sees Firebreak's own
/// exit status, and forwards only the four variables a GUI needs to find the
/// session — not the whole environment, which is what pkexec is careful to
/// drop.
#[cfg(any(target_os = "linux", test))]
pub fn launcher_script(exe: &str) -> String {
    format!(
        "#!/bin/sh\n\
         # Installed by `firebreak --install-desktop`. Starts Firebreak with the\n\
         # privilege it requires, keeping the session's display reachable.\n\
         set -eu\n\
         EXE={exe}\n\
         if [ \"$(id -u)\" = 0 ]; then\n\
         \x20   exec \"$EXE\" \"$@\"\n\
         fi\n\
         exec pkexec env \\\n\
         \x20   DISPLAY=\"${{DISPLAY-}}\" \\\n\
         \x20   WAYLAND_DISPLAY=\"${{WAYLAND_DISPLAY-}}\" \\\n\
         \x20   XDG_RUNTIME_DIR=\"${{XDG_RUNTIME_DIR-}}\" \\\n\
         \x20   XAUTHORITY=\"${{XAUTHORITY-}}\" \\\n\
         \x20   \"$EXE\" \"$@\"\n"
    )
}

/// The desktop entry. `Exec` points at the launcher, never at the binary
/// directly: launched straight, Firebreak would exit immediately with the
/// "must run as root" error and the user would see a window that never
/// appeared.
#[cfg(any(target_os = "linux", test))]
pub fn desktop_entry() -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Version=1.0\n\
         Name=Firebreak\n\
         Comment=Observe first. Enforce with confidence. Firewall rule-usage auditor\n\
         Exec={LAUNCHER}\n\
         Icon=firebreak\n\
         Terminal=false\n\
         Categories=System;Security;Monitor;\n\
         Keywords=firewall;firewalld;ufw;nftables;audit;\n\
         StartupNotify=true\n"
    )
}

/// Install the desktop entry, icon and launcher. Idempotent: run it again
/// after moving the binary and the launcher points at the new path.
#[cfg(target_os = "linux")]
pub fn install() -> Result<String> {
    use std::os::unix::fs::PermissionsExt;

    let exe = std::env::current_exe()
        .context("finding this executable's own path")?
        .canonicalize()
        .context("resolving this executable's path")?;
    let exe = exe.to_str().context("executable path is not valid UTF-8")?;
    // A path with a quote or whitespace would break out of the script's
    // assignment. Refuse rather than emit something that would run wrong.
    if exe.contains(['"', '\'', ' ', '\n', '$', '`', '\\']) {
        anyhow::bail!(
            "the executable path contains characters the launcher cannot quote safely: {exe}\n\
             Move it somewhere plain — /usr/local/bin/firebreak — and run this again."
        );
    }

    for (path, body, mode) in [
        (LAUNCHER, launcher_script(exe), 0o755),
        (DESKTOP_FILE, desktop_entry(), 0o644),
    ] {
        let dir = std::path::Path::new(path).parent().context("no parent")?;
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        std::fs::write(path, body).with_context(|| format!("writing {path}"))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("setting mode on {path}"))?;
    }

    // The icon is already inside the binary for the window's own title bar;
    // the theme needs it as a file under a name the entry can reference.
    let icon_dir = std::path::Path::new(ICON_FILE)
        .parent()
        .context("no parent")?;
    std::fs::create_dir_all(icon_dir)
        .with_context(|| format!("creating {}", icon_dir.display()))?;
    std::fs::write(ICON_FILE, crate::ui::APP_ICON_PNG)
        .with_context(|| format!("writing {ICON_FILE}"))?;

    // Best effort: most desktops notice a new entry on their own, and a
    // missing cache tool is not a failure worth refusing the install over.
    for (bin, args) in [
        ("update-desktop-database", vec!["/usr/share/applications"]),
        (
            "gtk-update-icon-cache",
            vec!["-q", "-t", "-f", "/usr/share/icons/hicolor"],
        ),
    ] {
        if let Some(path) = crate::syspath::system_tool(bin) {
            let _ = crate::syspath::command(path).args(&args).status();
        }
    }

    Ok(format!(
        "Installed the desktop entry. Firebreak now appears in the application menu \
         and asks for authorisation when launched.\n  {DESKTOP_FILE}\n  {ICON_FILE}\n  \
         {LAUNCHER} -> {exe}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_entry_launches_through_the_launcher_not_the_binary() {
        let e = desktop_entry();
        assert!(
            e.contains(&format!("Exec={LAUNCHER}")),
            "launching the binary directly would exit with 'must run as root' and \
             show the user nothing at all"
        );
        assert!(
            e.contains("Icon=firebreak"),
            "must match the installed icon name"
        );
        assert!(e.starts_with("[Desktop Entry]\n"));
        assert!(e.contains("Terminal=false"));
    }

    /// pkexec drops the environment. Without these four the process starts,
    /// finds no compositor and dies — which reads as "the launcher is broken".
    #[test]
    fn the_launcher_forwards_what_a_window_needs_to_open() {
        let s = launcher_script("/usr/local/bin/firebreak");
        for var in [
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "XDG_RUNTIME_DIR",
            "XAUTHORITY",
        ] {
            assert!(s.contains(&format!("{var}=")), "{var} must be forwarded");
        }
        assert!(s.contains("exec pkexec env"));
        assert!(s.starts_with("#!/bin/sh\n"));
    }

    /// Already root — from a terminal, or a desktop that elevated for us —
    /// must not prompt a second time.
    #[test]
    fn running_as_root_skips_the_prompt() {
        let s = launcher_script("/usr/local/bin/firebreak");
        let root_branch = s.find("id -u").expect("checks for root");
        let pkexec = s.find("exec pkexec").expect("elevates otherwise");
        assert!(root_branch < pkexec, "the root check has to come first");
        assert!(s.contains("exec \"$EXE\" \"$@\""));
    }
}
