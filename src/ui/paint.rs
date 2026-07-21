//! Rendering for the main window, split out of ui.rs. Chrome bands use egui
//! painting with explicit fonts/colors from the design tokens; the rule
//! table is custom-painted for exact grid, checkbox-intent, chip, and
//! accent-edge fidelity.

use super::{cell_text, interactive_chip, App, DirFilter, Phase, Sort, Tab};
use crate::listeners::{self, Listener};
use crate::theme::{self as t};
use crate::time_util;
use eframe::egui::{self, Align2, Color32, Pos2, Rect, Sense, Stroke, Vec2};

const TITLEBAR_H: f32 = 32.0;

// ---- vector glyphs (Plex + egui fallback lack ▲ ▾ ✕ ✓ ⌕) ----
mod glyph {
    use eframe::egui::{self, Color32, Pos2, Rect, Stroke, Vec2};

    pub fn check(p: &egui::Painter, center: Pos2, size: f32, color: Color32) {
        let s = size / 2.0;
        let a = Pos2::new(center.x - s, center.y - s * 0.1);
        let b = Pos2::new(center.x - s * 0.25, center.y + s * 0.6);
        let c = Pos2::new(center.x + s * 0.9, center.y - s * 0.7);
        let w = (size * 0.16).max(1.3);
        p.line_segment([a, b], Stroke::new(w, color));
        p.line_segment([b, c], Stroke::new(w, color));
    }

    pub fn cross(p: &egui::Painter, center: Pos2, size: f32, color: Color32) {
        let s = size / 2.0;
        let w = (size * 0.14).max(1.2);
        p.line_segment([Pos2::new(center.x - s, center.y - s), Pos2::new(center.x + s, center.y + s)], Stroke::new(w, color));
        p.line_segment([Pos2::new(center.x + s, center.y - s), Pos2::new(center.x - s, center.y + s)], Stroke::new(w, color));
    }

    pub fn tri_down(p: &egui::Painter, center: Pos2, size: f32, color: Color32) {
        let s = size / 2.0;
        p.add(egui::Shape::convex_polygon(
            vec![
                Pos2::new(center.x - s, center.y - s * 0.6),
                Pos2::new(center.x + s, center.y - s * 0.6),
                Pos2::new(center.x, center.y + s * 0.8),
            ],
            color,
            Stroke::NONE,
        ));
    }

    pub fn tri_up(p: &egui::Painter, center: Pos2, size: f32, color: Color32) {
        let s = size / 2.0;
        p.add(egui::Shape::convex_polygon(
            vec![
                Pos2::new(center.x - s, center.y + s * 0.6),
                Pos2::new(center.x + s, center.y + s * 0.6),
                Pos2::new(center.x, center.y - s * 0.8),
            ],
            color,
            Stroke::NONE,
        ));
    }

    /// Advisory triangle with a hollow center dot — reads as a warning mark.
    pub fn warn_tri(p: &egui::Painter, center: Pos2, size: f32, color: Color32) {
        tri_up(p, center, size, color);
    }

    /// Warning sign: filled triangle with a white exclamation mark.
    pub fn warn_sign(p: &egui::Painter, center: Pos2, size: f32, color: Color32) {
        let s = size / 2.0;
        p.add(egui::Shape::convex_polygon(
            vec![
                Pos2::new(center.x - s, center.y + s * 0.75),
                Pos2::new(center.x + s, center.y + s * 0.75),
                Pos2::new(center.x, center.y - s * 0.85),
            ],
            color,
            Stroke::NONE,
        ));
        // exclamation: stem + dot in white
        let top = center.y - s * 0.1;
        p.line_segment(
            [Pos2::new(center.x, top), Pos2::new(center.x, center.y + s * 0.25)],
            Stroke::new((size * 0.11).max(1.2), Color32::WHITE),
        );
        p.circle_filled(Pos2::new(center.x, center.y + s * 0.5), (size * 0.075).max(0.9), Color32::WHITE);
    }

    pub fn magnifier(p: &egui::Painter, center: Pos2, color: Color32) {
        let r = 4.0;
        let c = Pos2::new(center.x - 1.0, center.y - 1.0);
        p.circle_stroke(c, r, Stroke::new(1.3, color));
        p.line_segment(
            [Pos2::new(c.x + r * 0.7, c.y + r * 0.7), Pos2::new(c.x + r * 1.6, c.y + r * 1.6)],
            Stroke::new(1.3, color),
        );
    }

    /// Circled check — the "Reviewed" mark. Round on purpose: visually
    /// distinct from the square enable/disable checkbox.
    pub fn circle_check(p: &egui::Painter, center: Pos2, filled: bool, circle: Color32, mark: Color32) {
        if filled {
            p.circle_filled(center, 7.5, circle);
        } else {
            p.circle_stroke(center, 7.0, Stroke::new(1.3, circle));
        }
        let s = 7.5;
        p.line_segment(
            [Pos2::new(center.x - s * 0.32, center.y + s * 0.02), Pos2::new(center.x - s * 0.08, center.y + s * 0.30)],
            Stroke::new(1.5, mark),
        );
        p.line_segment(
            [Pos2::new(center.x - s * 0.08, center.y + s * 0.30), Pos2::new(center.x + s * 0.36, center.y - s * 0.26)],
            Stroke::new(1.5, mark),
        );
    }

    /// Sun: a small disc with eight rays (shown in dark mode → click for light).
    pub fn sun(p: &egui::Painter, center: Pos2, color: Color32) {
        p.circle_filled(center, 3.2, color);
        for i in 0..8 {
            let a = std::f32::consts::TAU * (i as f32) / 8.0;
            let (s, c) = a.sin_cos();
            let d = Pos2::new(center.x + c, center.y + s);
            p.line_segment(
                [Pos2::new(d.x + c * 4.0, d.y + s * 4.0), Pos2::new(d.x + c * 6.0, d.y + s * 6.0)],
                Stroke::new(1.2, color),
            );
        }
    }

    /// Crescent moon (shown in light mode → click for dark). `bg` carves the crescent.
    pub fn moon(p: &egui::Painter, center: Pos2, color: Color32, bg: Color32) {
        p.circle_filled(center, 5.0, color);
        p.circle_filled(Pos2::new(center.x + 2.6, center.y - 1.8), 4.4, bg);
    }

    pub fn minimize(p: &egui::Painter, center: Pos2, color: Color32) {
        p.line_segment([Pos2::new(center.x - 5.0, center.y), Pos2::new(center.x + 5.0, center.y)], Stroke::new(1.2, color));
    }

    /// Windowed → offer maximize: a single square.
    pub fn maximize(p: &egui::Painter, center: Pos2, color: Color32) {
        let r = Rect::from_center_size(center, Vec2::splat(9.0));
        p.rect_stroke(r, 0.0, Stroke::new(1.2, color));
    }

    /// Maximized → offer restore: two overlapping squares.
    pub fn restore(p: &egui::Painter, center: Pos2, color: Color32) {
        let s = 7.5;
        // back square (top-right)
        let back = Rect::from_min_size(Pos2::new(center.x - s / 2.0 + 2.0, center.y - s / 2.0 - 2.0), Vec2::splat(s));
        p.rect_stroke(back, 0.0, Stroke::new(1.1, color));
        // front square (bottom-left), painted over with the panel fill behind
        let front = Rect::from_min_size(Pos2::new(center.x - s / 2.0 - 2.0, center.y - s / 2.0 + 2.0), Vec2::splat(s));
        p.rect_filled(front, 0.0, crate::theme::TITLEBAR());
        p.rect_stroke(front, 0.0, Stroke::new(1.1, color));
    }
}

pub fn window(app: &mut App, ctx: &egui::Context) {
    if t::is_dark() != app.dark_mode {
        t::set_dark(app.dark_mode);
        t::apply_visuals(ctx);
    }
    titlebar(app, ctx);
    header(app, ctx);
    if let Some(hours) = app.young_evidence_hours() {
        if !app.warning_acked {
            warning_band(app, ctx, hours);
        }
    } else if !app.ctx_info.note.is_empty() {
        note_band(app, ctx);
    }
    if app.phase == Phase::NeedsEnable {
        firstrun_band(app, ctx);
    }
    filter_bar(app, ctx);
    footer(app, ctx);
    drawer(app, ctx);
    if app.selected.is_some() {
        detail_panel(app, ctx);
    }
    central(app, ctx);
    if app.confirm_open {
        confirm_modal(app, ctx);
    }
    about_box(app, ctx);
    // 1px window border on a foreground layer (we draw our own chrome)
    let screen = ctx.screen_rect();
    ctx.layer_painter(egui::LayerId::new(egui::Order::Foreground, egui::Id::new("winborder")))
        .rect_stroke(screen.shrink(0.5), 0.0, Stroke::new(1.0, t::BORDER()));
}

// ---- title bar ----

fn titlebar(app: &mut App, ctx: &egui::Context) {
    let logo = app.logo_texture(ctx);
    egui::TopBottomPanel::top("titlebar")
        .exact_height(TITLEBAR_H)
        .frame(egui::Frame::none().fill(t::TITLEBAR()))
        .show(ctx, |ui| {
            let rect = ui.max_rect();
            // window controls occupy the right ~138px; the rest is a drag zone
            let controls_w = 46.0 * 3.0;
            let drag_rect = Rect::from_min_max(rect.min, Pos2::new(rect.right() - controls_w, rect.bottom()));
            let drag = ui.interact(drag_rect, ui.id().with("tb_drag"), Sense::click_and_drag());
            if drag.drag_started() {
                ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
            }
            if drag.double_clicked() {
                let maxed = ctx.input(|i| i.viewport().maximized.unwrap_or(false));
                ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!maxed));
            }

            let p = ui.painter();
            super::stroke_bottom(p, rect, t::BORDER());
            let logo_rect = Rect::from_min_size(Pos2::new(rect.left() + 10.0, rect.center().y - 9.0), Vec2::splat(18.0));
            p.image(logo.id(), logo_rect, Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)), Color32::WHITE);
            let name_pos = Pos2::new(logo_rect.right() + 8.0, rect.center().y);
            let name_galley = p.layout_no_wrap("Firebreak".to_string(), t::semibold(12.0), t::INK());
            p.galley(Pos2::new(name_pos.x, name_pos.y - name_galley.size().y / 2.0), name_galley.clone(), t::INK());
            let host = if app.ctx_info.hostname.is_empty() { String::new() } else { format!(" · {}", app.ctx_info.hostname) };
            // catchline sits just after the name (small fixed gap), not floated far right
            p.text(Pos2::new(name_pos.x + name_galley.size().x + 12.0, rect.center().y), Align2::LEFT_CENTER, format!("— Observe First. Enforce with Confidence.{host}"), t::sans(11.0), t::FAINT());

            // min / max / close — each a 46px hit target
            let maximized = ctx.input(|i| i.viewport().maximized.unwrap_or(false));
            for i in 0..3u8 {
                let bx = Rect::from_min_size(Pos2::new(rect.right() - 46.0 * (3.0 - i as f32), rect.top()), Vec2::new(46.0, TITLEBAR_H));
                let r = ui.interact(bx, ui.id().with(("winbtn", i)), Sense::click());
                let hovered = r.hovered();
                if hovered {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                }
                let is_close = i == 2;
                if hovered {
                    ui.painter().rect_filled(bx, 0.0, if is_close { t::DESTRUCTIVE() } else { Color32::from_rgb(0xDE, 0xDC, 0xD8) });
                }
                let col = if hovered && is_close { Color32::WHITE } else { t::TERTIARY() };
                let c = bx.center();
                match i {
                    0 => glyph::minimize(ui.painter(), c, col),
                    1 => {
                        if maximized {
                            glyph::restore(ui.painter(), c, col);
                        } else {
                            glyph::maximize(ui.painter(), c, col);
                        }
                    }
                    _ => glyph::cross(ui.painter(), c, 9.0, col),
                }
                if r.clicked() {
                    match i {
                        0 => ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true)),
                        1 => ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized)),
                        _ => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
                    }
                }
            }
        });
}

// ---- evidence header ----

fn header(app: &mut App, ctx: &egui::Context) {
    egui::TopBottomPanel::top("header")
        .frame(egui::Frame::none().fill(t::TABLE_BG()).inner_margin(egui::Margin::symmetric(PAGE, 10.0)))
        .show(ctx, |ui| {
            super::stroke_bottom(ui.painter(), ui.max_rect().expand2(Vec2::new(PAGE, 10.0)), t::BORDER_LIGHT());
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                // before the audit check completes, don't assert "off"
                if !app.audit_checked && app.phase == Phase::Loading {
                    dot(ui, t::ADVISORY());
                    ui.add_space(8.0);
                    stat(ui, "Detecting…", "checking Windows audit policy");
                    return;
                }
                // enabling takes a few seconds — show progress, not "off"
                if app.phase == Phase::Enabling {
                    dot(ui, t::ADVISORY());
                    ui.add_space(8.0);
                    let cap = if app.progress.is_empty() { "please wait…".to_string() } else { app.progress.clone() };
                    stat(ui, "Enabling auditing…", &cap);
                    ui.add_space(10.0);
                    ui.spinner();
                    return;
                }
                let active = app.ctx_info.auditing_active;
                dot(ui, if active { t::LIVE() } else { t::CB_EMPTY_BORDER() });
                ui.add_space(8.0);
                if active {
                    let since = app
                        .ctx_info
                        .collection_started
                        .as_deref()
                        .map(time_util::since_with_age)
                        .unwrap_or_else(|| "just now".into());
                    stat(ui, "Auditing active", &format!("Since {since}"));
                    ui.add_space(12.0);
                    // Stop control — disables auditing (and returns to the
                    // first-run view, handy for testing that state too)
                    if flat_button(ui, "Stop").clicked() {
                        app.stop_auditing(ctx);
                    }
                    ui.add_space(12.0);
                } else {
                    stat(ui, "Auditing is off", "No connection data has ever been collected");
                }

                if active {
                    divider(ui);
                    let last = app
                        .ctx_info
                        .last_ingest
                        .as_deref()
                        .map(|s| format!("This run · Last Ingest {}", time_util::relative(s)))
                        .unwrap_or_else(|| "This run".into());
                    let events = if app.phase == Phase::Loading || app.phase == Phase::Enabling {
                        format!("Ingesting… {}", app.progress)
                    } else {
                        format!("{} events", t::fmt_thousands(app.ctx_info.events_processed as i64))
                    };
                    stat(ui, &events, &last);

                    divider(ui);
                    let gap = !app.ctx_info.note.is_empty();
                    let young = app.young_evidence_hours().is_some();
                    let value = if gap { "Coverage gap" } else { "Coverage complete" };
                    if young && app.warning_acked {
                        // warning persists but was dismissed — offer to reopen it
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 1.0;
                            ui.label(egui::RichText::new(value).font(t::semibold(12.0)).color(t::INK()));
                            if link(ui, "See warning", t::ADVISORY_HEADER()).clicked() {
                                app.warning_acked = false;
                            }
                        });
                    } else {
                        let caption = if gap || young {
                            "See warning below"
                        } else {
                            "No gaps detected in Audit Log"
                        };
                        stat(ui, value, caption);
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let settings = settings_button(ui);
                    let just_toggled = settings.clicked();
                    if just_toggled {
                        app.settings_open = !app.settings_open;
                    }
                    settings_menu(app, ui, ctx, settings.rect, just_toggled);
                    if active {
                        ui.add_space(8.0);
                        if flat_button(ui, "Refresh now").clicked() {
                            if let (Some(db), Phase::Ready) = (app.db_path.clone(), app.phase) {
                                app.phase = Phase::Loading;
                                app.spawn_detect(db, ctx.clone());
                            }
                        }
                    }
                    ui.add_space(8.0);
                    if theme_toggle(ui, app.dark_mode).clicked() {
                        app.dark_mode = !app.dark_mode;
                    }
                });
            });
        });
}

fn dot(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(8.0), Sense::hover());
    ui.painter().circle_filled(rect.center(), 4.0, color);
}

fn stat(ui: &mut egui::Ui, value: &str, caption: &str) {
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 1.0;
        ui.label(egui::RichText::new(value).font(t::semibold(12.0)).color(t::INK()));
        ui.label(egui::RichText::new(caption).font(t::sans(11.0)).color(t::TERTIARY()));
    });
}

fn divider(ui: &mut egui::Ui) {
    ui.add_space(24.0);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(1.0, 26.0), Sense::hover());
    ui.painter().vline(rect.center().x, rect.y_range(), Stroke::new(1.0, t::BORDER_LIGHT()));
    ui.add_space(24.0);
}

const PAGE: f32 = super::PAGE_PAD;

fn flat_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    let galley = ui.painter().layout_no_wrap(label.to_string(), t::sans(12.0), t::INK());
    let size = Vec2::new(galley.size().x + 24.0, galley.size().y + 10.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let (fill, border) = if resp.is_pointer_button_down_on() {
        (t::CHROME(), t::ACCENT())
    } else if resp.hovered() {
        (t::TABLE_BG(), t::ACCENT())
    } else {
        (t::RAISED(), t::CONTROL_BORDER())
    };
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    ui.painter().rect(rect, 0.0, fill, Stroke::new(1.0, border));
    ui.painter().galley(rect.center() - galley.size() / 2.0, galley, t::INK());
    resp
}

/// A text link that shows the hand cursor and underlines/darkens on hover.
fn link(ui: &mut egui::Ui, label: &str, color: Color32) -> egui::Response {
    let resp = ui.add(
        egui::Label::new(egui::RichText::new(label).font(t::sans(12.0)).color(color).underline())
            .sense(Sense::click()),
    );
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

/// Dropdown anchored under the Settings button.
fn settings_menu(app: &mut App, _ui: &mut egui::Ui, ctx: &egui::Context, anchor: Rect, just_toggled: bool) {
    if !app.settings_open {
        return;
    }
    let area = egui::Area::new(egui::Id::new("settings_menu"))
        .order(egui::Order::Foreground)
        .fixed_pos(Pos2::new(anchor.right() - 210.0, anchor.bottom() + 2.0));
    let resp = area.show(ctx, |ui| {
        egui::Frame::none()
            .fill(t::TABLE_BG())
            .stroke(Stroke::new(1.0, t::CONTROL_BORDER()))
            .inner_margin(egui::Margin::same(4.0))
            .show(ui, |ui| {
                ui.set_width(202.0);
                let ready = app.phase == Phase::Ready && app.db_path.is_some();
                if menu_item(ui, "Export usage to CSV…", app.phase == Phase::Ready && !app.rows.is_empty()) {
                    do_export_csv(app);
                    app.settings_open = false;
                }
                if menu_item(ui, "Import events from .evtx…", app.db_path.is_some()) {
                    app.settings_open = false;
                    do_import_evtx(app, ctx);
                }
                if menu_item(ui, "Import Firebreak export…", app.db_path.is_some()) {
                    app.settings_open = false;
                    do_import_bundle(app, ctx);
                }
                if menu_item(ui, "Save collection script (.ps1)…", true) {
                    app.settings_open = false;
                    do_save_collect_script(app);
                }
                if menu_item(ui, "Rescan entire log", ready) {
                    if let Some(db) = app.db_path.clone() {
                        let _ = crate::pipeline::reset(&db);
                        app.phase = Phase::Loading;
                        app.spawn_detect(db, ctx.clone());
                    }
                    app.settings_open = false;
                }
                if menu_item(ui, "Restore audit policy", app.db_path.is_some()) {
                    if let Some(db) = app.db_path.clone() {
                        if let Ok(store) = crate::store::Store::open(&db) {
                            app.status = match crate::pipeline::restore_audit_state(&store) {
                                Ok(m) => m,
                                Err(e) => format!("Restore failed: {e:#}"),
                            };
                        }
                    }
                    app.settings_open = false;
                }
                if menu_item(ui, "Open data folder", true) {
                    open_data_folder();
                    app.settings_open = false;
                }
                ui.separator();
                if menu_item(ui, "Check for updates…", true) {
                    app.about_open = true;
                    app.settings_open = false;
                    app.spawn_update_check(ctx.clone());
                }
                if menu_item(ui, "About Firebreak", true) {
                    app.about_open = true;
                    app.settings_open = false;
                }
            });
    });
    // click-away closes — but not on the very frame the Settings button was
    // clicked to open it (that click reads as "elsewhere" to the menu area)
    if !just_toggled && resp.response.clicked_elsewhere() {
        app.settings_open = false;
    }
}

fn open_data_folder() {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    let dir = std::path::Path::new(&base).join("firebreak");
    let _ = std::fs::create_dir_all(&dir);
    #[cfg(windows)]
    {
        let explorer = std::path::Path::new(
            &std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()),
        )
        .join("explorer.exe");
        let _ = crate::syspath::command(explorer).arg(&dir).spawn();
    }
}

#[cfg(windows)]
fn do_export_csv(app: &mut App) {
    let default = crate::pipeline::default_csv_name();
    if let Some(path) = rfd::FileDialog::new()
        .add_filter("CSV", &["csv"])
        .set_file_name(&default)
        .set_title("Export rule usage to CSV")
        .save_file()
    {
        app.status = match crate::pipeline::export_csv(&app.rows, &path) {
            Ok(()) => format!("Exported {} rules → {}", app.rows.len(), path.display()),
            Err(e) => format!("CSV export failed: {e:#}"),
        };
    }
}

#[cfg(not(windows))]
fn do_export_csv(app: &mut App) {
    // preview/dev: no dialog — write next to the working dir
    let path = std::path::PathBuf::from(crate::pipeline::default_csv_name());
    app.status = match crate::pipeline::export_csv(&app.rows, &path) {
        Ok(()) => format!("Exported {} rules → {}", app.rows.len(), path.display()),
        Err(e) => format!("CSV export failed: {e:#}"),
    };
}

#[cfg(windows)]
fn do_import_evtx(app: &mut App, ctx: &egui::Context) {
    let Some(path) = rfd::FileDialog::new()
        .add_filter("Windows event log", &["evtx"])
        .set_title("Import a saved Security .evtx")
        .pick_file()
    else {
        return;
    };
    // if an import session is already open, ask whether to add or start fresh
    let append = if app.import_db.is_some() {
        match rfd::MessageDialog::new()
            .set_title("Import events")
            .set_description(
                "Add these events to the current import (for reviewing multiple machines \
                 together)?\n\nYes = add · No = start a new import from just this file.",
            )
            .set_buttons(rfd::MessageButtons::YesNo)
            .show()
        {
            rfd::MessageDialogResult::Yes => true,
            _ => false,
        }
    } else {
        false
    };
    app.spawn_import(path, append, ctx.clone());
}

#[cfg(not(windows))]
fn do_import_evtx(app: &mut App, _ctx: &egui::Context) {
    app.status = "Import is only available on Windows.".into();
}

#[cfg(windows)]
fn do_import_bundle(app: &mut App, ctx: &egui::Context) {
    let Some(path) = rfd::FileDialog::new()
        .add_filter("Firebreak export", &["zip"])
        .set_title("Import a Firebreak export bundle")
        .pick_file()
    else {
        return;
    };
    app.spawn_import_bundle(path, ctx.clone());
}

#[cfg(not(windows))]
fn do_import_bundle(app: &mut App, _ctx: &egui::Context) {
    app.status = "Import is only available on Windows.".into();
}

/// Write the embedded PowerShell collector to disk for use on hosts that
/// can't run the exe.
#[cfg(windows)]
fn do_save_collect_script(app: &mut App) {
    let Some(path) = rfd::FileDialog::new()
        .add_filter("PowerShell script", &["ps1"])
        .set_file_name("firebreak-collect.ps1")
        .set_title("Save the offline collection script")
        .save_file()
    else {
        return;
    };
    app.status = match std::fs::write(&path, crate::collect::COLLECT_PS1) {
        Ok(()) => format!(
            "Saved collection script to {}. Run it elevated on the target device, then import the .zip it produces.",
            path.display()
        ),
        Err(e) => format!("Couldn't save script: {e}"),
    };
}

#[cfg(not(windows))]
fn do_save_collect_script(app: &mut App) {
    app.status = "Saving the collection script is only available on Windows.".into();
}

fn menu_item(ui: &mut egui::Ui, label: &str, enabled: bool) -> bool {
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 24.0), if enabled { Sense::click() } else { Sense::hover() });
    if enabled && resp.hovered() {
        ui.painter().rect_filled(rect, 0.0, t::ACCENT_TINT());
    }
    let col = if enabled { t::INK() } else { t::DISABLED() };
    ui.painter().text(Pos2::new(rect.left() + 8.0, rect.center().y), Align2::LEFT_CENTER, label, t::sans(12.0), col);
    enabled && resp.clicked()
}

fn about_box(app: &mut App, ctx: &egui::Context) {
    if !app.about_open {
        return;
    }
    egui::Area::new(egui::Id::new("about_scrim")).order(egui::Order::Background).show(ctx, |ui| {
        ui.painter().rect_filled(ctx.screen_rect(), 0.0, Color32::from_rgba_unmultiplied(28, 28, 30, 90));
    });
    let mut open = true;
    egui::Window::new("about")
        .title_bar(false)
        .collapsible(false)
        .resizable(false)
        .fixed_size(Vec2::new(360.0, 0.0))
        .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
        .frame(egui::Frame::none().fill(t::TABLE_BG()).stroke(Stroke::new(1.0, t::CONTROL_BORDER())))
        .show(ctx, |ui| {
            ui.add_space(18.0);
            let logo = app.logo_texture(ctx);
            ui.horizontal(|ui| {
                ui.add_space(20.0);
                let (r, _) = ui.allocate_exact_size(Vec2::splat(36.0), Sense::hover());
                ui.painter().image(logo.id(), r, Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)), Color32::WHITE);
                ui.add_space(8.0);
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("Firebreak").font(t::semibold(15.0)).color(t::INK()));
                    ui.label(egui::RichText::new(format!("Version {}", crate::pipeline::version_string())).font(t::mono(11.0)).color(t::SECONDARY()));
                });
            });
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                ui.add_space(20.0);
                ui.label(egui::RichText::new("Observe first. Enforce with confidence.").font(t::semibold(11.5)).color(t::ACCENT()));
            });
            ui.add_space(2.0);
            for line in [
                "Turn real network activity into least-privilege firewall policy.",
                "Correlates WFP connection audit events (5156/5157) with firewall",
                "rules to find unused and over-broad rules.",
            ] {
                ui.horizontal(|ui| {
                    ui.add_space(20.0);
                    ui.label(egui::RichText::new(line).font(t::sans(11.5)).color(t::SECONDARY()));
                });
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.add_space(20.0);
                ui.label(egui::RichText::new(format!("Host: {}", app.ctx_info.hostname)).font(t::mono(11.0)).color(t::TERTIARY()));
            });
            ui.add_space(16.0);
            about_updates(app, ui, ctx);
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_space(20.0);
                    if primary_button(ui, "Close", t::ACCENT()).clicked() {
                        open = false;
                    }
                });
            });
            ui.add_space(16.0);
        });
    if !open {
        app.about_open = false;
    }
}

/// The "Updates" section inside the About box: a one-line status and, when
/// there's something to do, a single primary button.
fn about_updates(app: &mut App, ui: &mut egui::Ui, ctx: &egui::Context) {
    use crate::ui::UpdateState;
    enum Act {
        None,
        Check,
        Download,
        Restart(std::path::PathBuf),
    }
    // snapshot the shared state, then release the lock before touching `app`
    let (line, color, act, btn): (String, Color32, Act, Option<&str>) = {
        let st = app.update.lock().unwrap();
        match &*st {
            UpdateState::Idle => ("Check whether a newer build is available.".into(), t::SECONDARY(), Act::Check, Some("Check now")),
            UpdateState::Checking => ("Checking for updates…".into(), t::SECONDARY(), Act::None, None),
            UpdateState::UpToDate(v) => (format!("You're on the latest version ({v})."), t::SECONDARY(), Act::None, None),
            UpdateState::Available(rel) if crate::update::signing_configured() => (format!("Version {} is available (you have {}).", rel.latest, rel.current), t::INK(), Act::Download, Some("Download & install")),
            // a newer build exists but this build can't verify a signed
            // download, so in-app install is withheld (fail closed)
            UpdateState::Available(rel) => (format!("Version {} is available (you have {}). Download it from the Releases page — in-app update is disabled in this build.", rel.latest, rel.current), t::ADVISORY_TEXT(), Act::None, None),
            UpdateState::Downloading => ("Downloading update…".into(), t::SECONDARY(), Act::None, None),
            UpdateState::Ready(exe) => ("Update installed — restart to finish.".into(), t::INK(), Act::Restart(exe.clone()), Some("Restart now")),
            UpdateState::Error(e) => (e.clone(), t::DESTRUCTIVE(), Act::Check, Some("Try again")),
        }
    };

    ui.horizontal(|ui| {
        ui.add_space(20.0);
        ui.label(egui::RichText::new("UPDATES").font(t::semibold(9.5)).color(t::TERTIARY()));
    });
    ui.add_space(4.0);
    ui.horizontal_wrapped(|ui| {
        ui.add_space(20.0);
        ui.set_max_width(300.0);
        ui.spacing_mut().item_spacing.x = 0.0;
        ui.label(egui::RichText::new(&line).font(t::sans(11.5)).color(color));
    });
    if let Some(label) = btn {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.add_space(20.0);
            if primary_button(ui, label, t::ACCENT()).clicked() {
                match act {
                    Act::Check => app.spawn_update_check(ctx.clone()),
                    Act::Download => app.spawn_update_download(ctx.clone()),
                    Act::Restart(exe) => crate::update::restart(&exe),
                    Act::None => {}
                }
            }
        });
    }
}

/// Small square icon button toggling light/dark. Shows the mode it switches *to*.
fn theme_toggle(ui: &mut egui::Ui, dark: bool) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(28.0, 28.0), Sense::click());
    let (fill, border) = if resp.hovered() { (t::TABLE_BG(), t::ACCENT()) } else { (t::RAISED(), t::CONTROL_BORDER()) };
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    ui.painter().rect(rect, 0.0, fill, Stroke::new(1.0, border));
    if dark {
        glyph::sun(ui.painter(), rect.center(), t::SECONDARY());
    } else {
        glyph::moon(ui.painter(), rect.center(), t::SECONDARY(), fill);
    }
    resp.on_hover_text(if dark { "Switch to light mode" } else { "Switch to dark mode" })
}

/// "Settings ▾" with a drawn caret.
fn settings_button(ui: &mut egui::Ui) -> egui::Response {
    let galley = ui.painter().layout_no_wrap("Settings".to_string(), t::sans(12.0), t::INK());
    let size = Vec2::new(galley.size().x + 34.0, galley.size().y + 10.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let (fill, border) = if resp.hovered() { (t::TABLE_BG(), t::ACCENT()) } else { (t::RAISED(), t::CONTROL_BORDER()) };
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    ui.painter().rect(rect, 0.0, fill, Stroke::new(1.0, border));
    ui.painter().galley(Pos2::new(rect.left() + 12.0, rect.center().y - galley.size().y / 2.0), galley, t::INK());
    glyph::tri_down(ui.painter(), Pos2::new(rect.right() - 12.0, rect.center().y), 8.0, t::TERTIARY());
    resp
}

// ---- warning band ----

fn warning_band(app: &mut App, ctx: &egui::Context, hours: f64) {
    egui::TopBottomPanel::top("warning")
        .frame(egui::Frame::none().fill(t::ADVISORY_BG()).inner_margin(egui::Margin::symmetric(PAGE, 8.0)))
        .show(ctx, |ui| {
            super::stroke_bottom(ui.painter(), ui.max_rect().expand2(Vec2::new(PAGE, 8.0)), t::ADVISORY_BORDER());
            ui.horizontal(|ui| {
                // drawn warning triangle with an exclamation, not a text glyph
                let (r, _) = ui.allocate_exact_size(Vec2::new(15.0, 15.0), Sense::hover());
                glyph::warn_sign(ui.painter(), r.center(), 13.0, t::ADVISORY());
                ui.add_space(6.0);
                let human = if hours < 48.0 {
                    format!("Only {} hours of evidence.", hours.round() as i64)
                } else {
                    format!("Only {} days of evidence.", (hours / 24.0).round() as i64)
                };
                let mut job = egui::text::LayoutJob::default();
                job.append(&human, 0.0, fmt(t::semibold(12.0), t::ADVISORY_TEXT()));
                job.append(
                    "  Zero-hit values are not yet meaningful — weekly and monthly traffic hasn't \
                     had a chance to occur.",
                    0.0,
                    fmt(t::sans(12.0), t::ADVISORY_TEXT()),
                );
                ui.label(job);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if link(ui, "Acknowledge", t::ADVISORY_HEADER()).clicked() {
                        app.warning_acked = true;
                    }
                });
            });
        });
}

fn note_band(app: &App, ctx: &egui::Context) {
    egui::TopBottomPanel::top("note")
        .frame(egui::Frame::none().fill(t::ADVISORY_BG()).inner_margin(egui::Margin::symmetric(PAGE, 8.0)))
        .show(ctx, |ui| {
            super::stroke_bottom(ui.painter(), ui.max_rect().expand2(Vec2::new(PAGE, 8.0)), t::ADVISORY_BORDER());
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("▲").font(t::sans(12.0)).color(t::ADVISORY()));
                ui.add_space(6.0);
                ui.label(egui::RichText::new(&app.ctx_info.note).font(t::sans(12.0)).color(t::ADVISORY_TEXT()));
            });
        });
}

fn fmt(font: egui::FontId, color: Color32) -> egui::text::TextFormat {
    egui::text::TextFormat { font_id: font, color, ..Default::default() }
}

// ---- first-run band ----

fn firstrun_band(app: &mut App, ctx: &egui::Context) {
    egui::TopBottomPanel::top("firstrun")
        .frame(egui::Frame::none().fill(t::ACCENT_TINT()).inner_margin(egui::Margin::symmetric(PAGE, 12.0)))
        .show(ctx, |ui| {
            super::stroke_bottom(ui.painter(), ui.max_rect().expand2(Vec2::new(PAGE, 12.0)), t::ACCENT_TINT_BORDER());
            ui.horizontal(|ui| {
                let enabling = app.phase == Phase::Enabling;
                let label = if enabling { "Enabling…" } else { "Enable connection auditing" };
                let galley = ui.painter().layout_no_wrap(label.to_string(), t::semibold(13.0), Color32::WHITE);
                let size = Vec2::new(galley.size().x + 40.0, galley.size().y + 16.0);
                let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
                let fill = if enabling { t::ACCENT().gamma_multiply(0.6) } else if resp.hovered() { t::ACCENT().gamma_multiply(1.1) } else { t::ACCENT() };
                ui.painter().rect_filled(rect, 0.0, fill);
                ui.painter().galley(rect.center() - galley.size() / 2.0, galley, Color32::WHITE);
                if resp.clicked() && !enabling {
                    app.start_enable(ctx);
                }
                ui.add_space(16.0);
                // constrain the explainer to the space left of the buttons so
                // it wraps instead of running off the window
                let w = (ui.available_width() - 8.0).max(120.0);
                ui.allocate_ui_with_layout(Vec2::new(w, 0.0), egui::Layout::top_down(egui::Align::Min), |ui| {
                    let mut job = egui::text::LayoutJob::default();
                    job.wrap.max_width = w;
                    job.append(
                        "Turns on Windows Filtering Platform audit events (security log, ~40 MB/day at typical load). ",
                        0.0, fmt(t::sans(12.0), t::INK()));
                    job.append("Nothing is blocked or modified", 0.0, fmt(t::semibold(12.0), t::INK()));
                    job.append(
                        " — firebreak only records which rules the traffic matches. Usage columns fill in as evidence \
                         accumulates; plan on ~7–14 days before zero-hit values mean anything.",
                        0.0, fmt(t::sans(12.0), t::INK()));
                    ui.label(job);
                });
            });
        });
}

// ---- filter bar ----

const CTRL_H: f32 = 25.0; // shared height for all filter-bar controls

fn filter_bar(app: &mut App, ctx: &egui::Context) {
    egui::TopBottomPanel::top("filterbar")
        .frame(egui::Frame::none().fill(t::CHROME()).inner_margin(egui::Margin::symmetric(PAGE, 7.0)))
        .show(ctx, |ui| {
            super::stroke_bottom(ui.painter(), ui.max_rect().expand2(Vec2::new(PAGE, 7.0)), t::BORDER_LIGHT());
            // one row, everything vertically centered to CTRL_H so the groups
            // line up exactly
            ui.horizontal(|ui| {
                ui.set_height(CTRL_H);
                ui.spacing_mut().item_spacing = Vec2::new(6.0, 0.0);

                // search box — reserve the field rect first, draw the
                // magnifier at a FIXED left inset, then place the TextEdit
                // with its text indented past the icon (no overlap, icon
                // doesn't move with the text)
                let (field, _) = ui.allocate_exact_size(Vec2::new(224.0, CTRL_H), Sense::hover());
                ui.painter().rect(field, 0.0, t::TABLE_BG(), Stroke::new(1.0, t::CONTROL_BORDER()));
                glyph::magnifier(ui.painter(), Pos2::new(field.left() + 12.0, field.center().y), t::FAINT());
                let text_area = Rect::from_min_max(
                    Pos2::new(field.left() + 24.0, field.top()),
                    Pos2::new(field.right() - 6.0, field.bottom()),
                );
                let mut child = ui.child_ui(text_area, egui::Layout::left_to_right(egui::Align::Center), None);
                child.add(
                    egui::TextEdit::singleline(&mut app.filter_text)
                        .hint_text("Filter rules…")
                        .desired_width(f32::INFINITY)
                        .font(t::sans(12.0))
                        .frame(false),
                );

                // direction filter (default In) — the primary audit lens
                let dir = app.dir_filter;
                let mut new_dir = dir;
                segmented_choice(ui, &[
                    ("In", DirFilter::In, "Show only inbound rules (traffic arriving at this PC)"),
                    ("Out", DirFilter::Out, "Show only outbound rules (traffic this PC initiates)"),
                    ("All", DirFilter::All, "Show both inbound and outbound rules"),
                ], dir, &mut new_dir);
                app.dir_filter = new_dir;

                ui.add_space(4.0);
                let zero_enabled = app.ctx_info.auditing_active;
                segmented_toggles(ui, &mut [
                    ("Enabled only", &mut app.only_enabled, true, "Show only rules that are currently enabled (hide disabled ones)"),
                    ("Zero-hit", &mut app.only_zero_hit, zero_enabled, "Show only rules with no observed traffic — the disable candidates"),
                    ("Flagged", &mut app.only_flagged, true, "Show only rules with a security advisory (e.g. RDP, SMB-inbound, broad allow, mDNS)"),
                    ("Hide reviewed", &mut app.hide_reviewed, true, "Hide rules you've marked as reviewed (the circle in the right-most column) — tick rules off to work the list down to zero"),
                ]);
                ui.add_space(4.0);
                segmented_toggles(ui, &mut [
                    ("Domain", &mut app.show_domain, true, "Include rules active on the Domain profile (corporate/AD network)"),
                    ("Private", &mut app.show_private, true, "Include rules active on the Private profile (home/trusted network)"),
                    ("Public", &mut app.show_public, true, "Include rules active on the Public profile (untrusted/public network)"),
                ]);

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let total = app.rows.len();
                    let shown = app.visible().len();
                    let mut job = egui::text::LayoutJob::default();
                    job.append(&t::fmt_thousands(total as i64), 0.0, fmt(t::semibold(11.5), t::INK()));
                    job.append(" rules · ", 0.0, fmt(t::sans(11.5), t::TERTIARY()));
                    job.append(&t::fmt_thousands(shown as i64), 0.0, fmt(t::semibold(11.5), t::INK()));
                    job.append(" shown", 0.0, fmt(t::sans(11.5), t::TERTIARY()));
                    ui.label(job);
                });
            });
        });
}

/// One segment cell of a segmented control; returns its click response.
/// `first` controls the left border; height is fixed to CTRL_H so groups
/// align regardless of label width.
fn segment_cell(ui: &mut egui::Ui, label: &str, active: bool, enabled: bool, first: bool, tooltip: &str) -> egui::Response {
    let text_col = if active { Color32::WHITE } else if enabled { t::SECONDARY() } else { t::CB_EMPTY_BORDER() };
    let galley = ui.painter().layout_no_wrap(label.to_string(), t::sans(11.5), text_col);
    let w = galley.size().x + 20.0;
    // sense hover even when disabled so the tooltip still shows
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, CTRL_H), Sense::click());
    let fill = if active { t::DARK_SEGMENT() } else if resp.hovered() && enabled { t::HOVER_WASH() } else { t::TABLE_BG() };
    ui.painter().rect_filled(rect, 0.0, fill);
    let border = Stroke::new(1.0, t::CONTROL_BORDER());
    ui.painter().hline(rect.x_range(), rect.top() + 0.5, border);
    ui.painter().hline(rect.x_range(), rect.bottom() - 0.5, border);
    ui.painter().vline(rect.right() - 0.5, rect.y_range(), border);
    if first {
        ui.painter().vline(rect.left() + 0.5, rect.y_range(), border);
    }
    ui.painter().galley(rect.center() - galley.size() / 2.0, galley, text_col);
    if resp.hovered() && enabled {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    if !tooltip.is_empty() {
        resp.clone().on_hover_text(tooltip);
    }
    resp
}

/// Segmented multi-toggle (each cell independently on/off).
fn segmented_toggles(ui: &mut egui::Ui, segs: &mut [(&str, &mut bool, bool, &str)]) {
    let prev = ui.spacing().item_spacing;
    ui.spacing_mut().item_spacing.x = 0.0;
    for (i, (label, state, enabled, tip)) in segs.iter_mut().enumerate() {
        if segment_cell(ui, label, **state, *enabled, i == 0, tip).clicked() && *enabled {
            **state = !**state;
        }
    }
    ui.spacing_mut().item_spacing = prev;
}

/// Segmented single-choice (exactly one active).
fn segmented_choice<T: PartialEq + Copy>(ui: &mut egui::Ui, segs: &[(&str, T, &str)], current: T, out: &mut T) {
    let prev = ui.spacing().item_spacing;
    ui.spacing_mut().item_spacing.x = 0.0;
    for (i, (label, val, tip)) in segs.iter().enumerate() {
        if segment_cell(ui, label, *val == current, true, i == 0, tip).clicked() {
            *out = *val;
        }
    }
    ui.spacing_mut().item_spacing = prev;
}

// ---- central: table + empty state ----

struct Cols {
    check: f32,
    name: (f32, f32),
    dir: (f32, f32),
    action: (f32, f32),
    profiles: (f32, f32),
    scope: (f32, f32),
    hits: (f32, f32),
    last: (f32, f32),
    apps: (f32, f32),
    listen: (f32, f32),
    reviewed: (f32, f32),
}

impl Cols {
    fn compute(left: f32, width: f32, cw: &super::ColWidths) -> Cols {
        let fixed_others = 34.0 + cw.dir + cw.action + cw.profiles + cw.scope + cw.hits + cw.last + cw.listen + cw.reviewed;
        let (name_w, apps_w) = if cw.name > 0.0 {
            // Rule pinned to a set width; Apps takes the remaining flex
            let name_w = cw.name.clamp(120.0, width - fixed_others - 100.0);
            (name_w, (width - fixed_others - name_w).max(100.0))
        } else {
            // auto: Rule and Apps share the flex
            let flex = (width - fixed_others).max(300.0);
            let name_w = (flex * (1.35 / 2.35)).max(190.0);
            (name_w, (flex - name_w).max(100.0))
        };
        let mut x = left;
        let mut col = |w: f32| {
            let a = x;
            x += w;
            (a, w)
        };
        Cols {
            check: col(34.0).0,
            name: col(name_w),
            dir: col(cw.dir),
            action: col(cw.action),
            profiles: col(cw.profiles),
            scope: col(cw.scope),
            hits: col(cw.hits),
            last: col(cw.last),
            apps: col(apps_w),
            listen: col(cw.listen),
            reviewed: col(cw.reviewed),
        }
    }
}

/// Text indent inside a column cell so content isn't flush against the
/// separator on its left.
const CELL_PAD: f32 = 8.0;

fn central(app: &mut App, ctx: &egui::Context) {
    egui::CentralPanel::default()
        .frame(egui::Frame::none().fill(t::TABLE_BG()))
        .show(ctx, |ui| {
            if app.rows.is_empty() && matches!(app.phase, Phase::Loading | Phase::Enabling) {
                ui.centered_and_justified(|ui| {
                    ui.label(egui::RichText::new(&app.progress).font(t::sans(12.0)).color(t::SECONDARY()));
                });
                return;
            }
            let full = ui.max_rect();
            let cw = app.col_w;
            let cols = Cols::compute(full.left(), full.width(), &cw);
            let visible = app.visible();
            if visible.is_empty() {
                table_header(ui, app, &cols);
                empty_state(app, ui);
                return;
            }
            // rows first, in the area below the header…
            let row_area = Rect::from_min_max(
                Pos2::new(full.left(), full.top() + HEADER_H),
                full.max,
            );
            let mut child = ui.child_ui(row_area, egui::Layout::top_down(egui::Align::Min), None);
            egui::ScrollArea::vertical().auto_shrink([false; 2]).show_rows(
                &mut child,
                ROW_H,
                visible.len(),
                |ui, range| {
                    for vi in range {
                        let ri = visible[vi];
                        let (rect, resp) = ui.allocate_exact_size(Vec2::new(cols.reviewed.0 + cols.reviewed.1 - full.left(), ROW_H), Sense::click());
                        let rc = Cols::compute(rect.left(), rect.width(), &cw);
                        row(app, ui, ri, rect, &rc, resp);
                    }
                },
            );
            // …then the header on top, so its bottom rule is always visible
            // even when rows scroll up under it
            table_header(ui, app, &cols);
        });
}

/// Column boundaries that carry a draggable resize handle. Each entry is
/// (boundary_x, width selector, drag sign). Most boundaries resize the
/// column to their left (sign +1). The Apps|Listening boundary resizes
/// Listening (to its right) so it grows when dragged left (sign −1).
fn resize_handles(app: &mut App, ui: &mut egui::Ui, cols: &Cols, header_rect: Rect) {
    // Rule width is "auto" (0) until first dragged — seed it with the
    // current computed width so the drag starts from the right place.
    let name_seed = cols.name.1;
    let edges: [(f32, fn(&mut super::ColWidths) -> &mut f32, f32); 9] = [
        (cols.name.0 + cols.name.1, |c| &mut c.name, 1.0), // Rule
        (cols.dir.0 + cols.dir.1, |c| &mut c.dir, 1.0),
        (cols.action.0 + cols.action.1, |c| &mut c.action, 1.0),
        (cols.profiles.0 + cols.profiles.1, |c| &mut c.profiles, 1.0),
        (cols.scope.0 + cols.scope.1, |c| &mut c.scope, 1.0),
        (cols.hits.0 + cols.hits.1, |c| &mut c.hits, 1.0),
        (cols.last.0 + cols.last.1, |c| &mut c.last, 1.0),
        (cols.listen.0, |c| &mut c.listen, -1.0),   // Listening (left edge)
        (cols.reviewed.0, |c| &mut c.reviewed, -1.0), // Reviewed (left edge)
    ];
    for (i, (x, sel, sign)) in edges.into_iter().enumerate() {
        let hit = Rect::from_min_max(Pos2::new(x - 3.0, header_rect.top()), Pos2::new(x + 3.0, header_rect.bottom()));
        let resp = ui.interact(hit, ui.id().with(("colresize", i)), Sense::drag());
        if resp.hovered() || resp.dragged() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeHorizontal);
            ui.painter().vline(x, header_rect.y_range(), Stroke::new(1.0, t::ACCENT()));
        }
        if resp.dragged() {
            // seed Rule's width the first time it's dragged
            if i == 0 && app.col_w.name == 0.0 {
                app.col_w.name = name_seed;
            }
            let w = sel(&mut app.col_w);
            *w = (*w + sign * resp.drag_delta().x).clamp(60.0, 500.0);
        }
    }
}

use super::ROW_H;
use super::HEADER_H;

fn table_header(ui: &mut egui::Ui, app: &mut App, cols: &Cols) {
    let full = ui.max_rect();
    let rect = Rect::from_min_size(full.min, Vec2::new(full.width(), HEADER_H));
    let p = ui.painter();
    p.rect_filled(rect, 0.0, t::RAISED());
    let font = t::semibold(11.0);
    let c = t::SECONDARY();
    let y = rect.center().y;
    let th = |x: f32, s: &str, col: Color32| {
        ui.painter().text(Pos2::new(x + CELL_PAD, y), Align2::LEFT_CENTER, s, font.clone(), col);
    };
    let _ = th; // header cells now drawn via header_cell
    let young = app.young_evidence_hours().is_some();
    let usage_hidden = app.phase == Phase::NeedsEnable;

    // every column header is clickable to sort by it
    if header_cell(app, ui, cols.name, rect, "Rule", Sort::Name, c).clicked() { toggle_sort(app, Sort::Name); }
    if header_cell(app, ui, cols.dir, rect, "Dir", Sort::Dir, c).clicked() { toggle_sort(app, Sort::Dir); }
    if header_cell(app, ui, cols.action, rect, "Action", Sort::Action, c).clicked() { toggle_sort(app, Sort::Action); }
    if header_cell(app, ui, cols.profiles, rect, "Profiles", Sort::Profiles, c).clicked() { toggle_sort(app, Sort::Profiles); }
    if header_cell(app, ui, cols.scope, rect, "Scope", Sort::Scope, c).clicked() { toggle_sort(app, Sort::Scope); }

    if usage_hidden {
        ui.painter().text(Pos2::new(cols.hits.0 + CELL_PAD, y), Align2::LEFT_CENTER, "Hits · Last seen · Apps", font.clone(), t::CB_EMPTY_BORDER());
        ui.painter().text(Pos2::new(cols.hits.0 + 128.0, y), Align2::LEFT_CENTER, "requires auditing", t::italic(11.0), t::CB_EMPTY_BORDER());
    } else {
        // young-evidence tint on hits/last (inset 1px so the bottom border shows)
        if young {
            let inset = |c: (f32, f32)| Rect::from_min_max(Pos2::new(c.0, rect.top()), Pos2::new(c.0 + c.1, rect.bottom() - 1.0));
            ui.painter().rect_filled(inset(cols.hits), 0.0, t::ADVISORY_BG());
            ui.painter().rect_filled(inset(cols.last), 0.0, t::ADVISORY_BG());
        }
        let usage_col = if young { t::ADVISORY_HEADER() } else { c };
        if header_cell(app, ui, cols.hits, rect, "Hits A / B", Sort::Hits, if young { t::ADVISORY_HEADER() } else { t::INK() }).clicked() { toggle_sort(app, Sort::Hits); }
        if header_cell(app, ui, cols.last, rect, "Last seen", Sort::LastSeen, usage_col).clicked() { toggle_sort(app, Sort::LastSeen); }
        if header_cell(app, ui, cols.apps, rect, "Apps observed", Sort::Apps, c).clicked() { toggle_sort(app, Sort::Apps); }
        if header_cell(app, ui, cols.listen, rect, "Listening now", Sort::Listening, c).clicked() { toggle_sort(app, Sort::Listening); }
    }
    if header_cell(app, ui, cols.reviewed, rect, "Reviewed", Sort::Reviewed, c).clicked() { toggle_sort(app, Sort::Reviewed); }
    // column separators
    for x in [cols.name.0, cols.dir.0, cols.action.0, cols.profiles.0, cols.scope.0, cols.hits.0, cols.last.0, cols.apps.0, cols.listen.0, cols.reviewed.0] {
        ui.painter().vline(x, rect.y_range(), Stroke::new(1.0, t::BORDER_LIGHT()));
    }
    // resize handles on the fixed-column right edges
    resize_handles(app, ui, cols, rect);
    // bottom border last, full width and on top of the yellow fills
    ui.painter().hline(rect.x_range(), rect.bottom() - 0.5, Stroke::new(1.0, t::CONTROL_BORDER()));
}

fn toggle_sort(app: &mut App, key: Sort) {
    if app.sort == key {
        app.sort_asc = !app.sort_asc;
    } else {
        app.sort = key;
        app.sort_asc = key.default_ascending();
    }
}

/// Draw a clickable column header: label at `x` (indented), plus the active
/// sort arrow after it. Returns the click response for the whole cell.
fn header_cell(app: &mut App, ui: &mut egui::Ui, col: (f32, f32), rect: Rect, label: &str, key: Sort, color: Color32) -> egui::Response {
    let font = t::semibold(11.0);
    let y = rect.center().y;
    ui.painter().text(Pos2::new(col.0 + CELL_PAD, y), Align2::LEFT_CENTER, label, font.clone(), color);
    if app.sort == key {
        let g = ui.painter().layout_no_wrap(label.to_string(), font, color);
        let ax = col.0 + CELL_PAD + g.size().x + 7.0;
        if app.sort_asc {
            glyph::tri_up(ui.painter(), Pos2::new(ax, y), 8.0, color);
        } else {
            glyph::tri_down(ui.painter(), Pos2::new(ax, y), 8.0, color);
        }
    }
    let cell = Rect::from_min_size(Pos2::new(col.0, rect.top()), Vec2::new(col.1, HEADER_H));
    let resp = ui.interact(cell, ui.id().with(("sort", label)), Sense::click());
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

fn row(app: &mut App, ui: &mut egui::Ui, ri: usize, rect: Rect, cols: &Cols, resp: egui::Response) {
    // apply-phase status for this rule, if any
    let apply_status = app.apply.as_ref().and_then(|a| {
        let r = &app.rows[ri];
        if !(r.pending() || a.results.contains_key(&r.rule.name)) {
            return None;
        }
        Some(match a.results.get(&r.rule.name) {
            Some(Ok(())) => RowApply::Done,
            Some(Err(e)) => RowApply::Failed(e.clone()),
            None if a.current.as_deref() == Some(r.rule.name.as_str()) => RowApply::Active(r.target_enabled),
            None if !a.finished => RowApply::Queued,
            None => RowApply::Pending,
        })
    });

    let r = &app.rows[ri];
    let selected = app.selected == Some(ri);
    let pending = r.pending();
    let saved_on = r.rule.is_enabled();
    let dimmed = !saved_on && !pending;
    let failed = matches!(apply_status, Some(RowApply::Failed(_)));

    // background
    let bg = if failed {
        t::FAIL_BG()
    } else if selected {
        t::SELECTED_ROW()
    } else if pending {
        t::ACCENT_TINT()
    } else if resp.hovered() {
        t::HOVER_WASH()
    } else {
        t::TABLE_BG()
    };
    let p = ui.painter();
    p.rect_filled(rect, 0.0, bg);
    p.hline(rect.x_range(), rect.bottom() - 0.5, Stroke::new(1.0, t::ROW_BORDER()));
    // faint column separators, aligned with the header's
    let sep = Stroke::new(1.0, t::ROW_BORDER());
    for x in [cols.name.0, cols.dir.0, cols.action.0, cols.profiles.0, cols.scope.0, cols.hits.0, cols.last.0, cols.apps.0, cols.listen.0, cols.reviewed.0] {
        p.vline(x, rect.y_range(), sep);
    }
    // edge bar
    if failed {
        p.rect_filled(Rect::from_min_size(rect.min, Vec2::new(3.0, rect.height())), 0.0, t::DESTRUCTIVE());
    } else if pending {
        p.rect_filled(Rect::from_min_size(rect.min, Vec2::new(3.0, rect.height())), 0.0, t::ACCENT());
    }

    let queued_dim = matches!(apply_status, Some(RowApply::Queued));
    let text_col = if dimmed || queued_dim { t::DISABLED() } else { t::INK() };

    // checkbox — indeterminate when the rule stays on but its profile scope
    // was narrowed
    let partial = r.target_enabled
        && !r.target_profiles.is_empty()
        && r.target_profiles != r.orig_profiles();
    let cb_rect = Rect::from_center_size(Pos2::new(cols.check + 17.0, rect.center().y), Vec2::splat(13.0));
    draw_checkbox(ui.painter(), cb_rect, saved_on, pending, r.target_enabled, partial);
    let cb_resp = ui.interact(cb_rect.expand(3.0), ui.id().with(("cb", ri)), Sense::click());

    // name (+ flag)
    let name_font = if pending && !dimmed { t::medium(12.0) } else { t::sans(12.0) };
    let flag_pad = if !r.flags.is_empty() { 16.0 } else { 0.0 };
    let name_rect = Rect::from_min_size(Pos2::new(cols.name.0, rect.top()), Vec2::new(cols.name.1 - CELL_PAD - flag_pad, rect.height()));
    cell_text(ui.painter(), name_rect, &r.rule.display_name, name_font, text_col, CELL_PAD);
    if !r.flags.is_empty() {
        // width of name for flag placement
        let g = ui.painter().layout_no_wrap(r.rule.display_name.clone(), t::sans(12.0), t::ADVISORY());
        let fx = (cols.name.0 + CELL_PAD + g.size().x + 8.0).min(cols.name.0 + cols.name.1 - 10.0);
        glyph::warn_tri(ui.painter(), Pos2::new(fx, rect.center().y), 9.0, t::ADVISORY());
    }

    // dir / action
    cell_text(ui.painter(), col_rect(cols.dir, rect), dir_short(&r.rule.direction), t::sans(11.5), if dimmed { t::DISABLED() } else { t::TERTIARY() }, CELL_PAD);
    let act_col = if dimmed { t::DISABLED() } else if r.rule.action.eq_ignore_ascii_case("block") { t::BLOCK() } else { t::INK() };
    cell_text(ui.painter(), col_rect(cols.action, rect), act_short(&r.rule.action), t::sans(12.0), act_col, CELL_PAD);

    // profiles chips — clickable to toggle a profile off/on for this rule
    let orig = r.orig_profiles();
    let target = r.target_profiles;
    let mut clicked_profile: Option<u8> = None;
    let mut cx = cols.profiles.0 + CELL_PAD;
    let editable = app.apply.is_none() && app.phase == Phase::Ready;
    for (bit, present, kept, label) in [
        (0u8, orig.domain, target.domain, "Domain"),
        (1, orig.private, target.private, "Private"),
        (2, orig.public, target.public, "Public"),
    ] {
        if !present {
            continue;
        }
        let (w, resp) = interactive_chip(ui, Pos2::new(cx, rect.center().y - 7.5), label, kept, editable, (ri, bit));
        cx += w;
        if resp.map_or(false, |r| r.clicked()) {
            clicked_profile = Some(bit);
        }
    }

    // scope (mono)
    cell_text(ui.painter(), Rect::from_min_size(Pos2::new(cols.scope.0, rect.top()), Vec2::new(cols.scope.1 - CELL_PAD, rect.height())), &listeners::scope_summary(&r.rule), t::mono(11.0), if dimmed { t::DISABLED() } else { t::SECONDARY() }, CELL_PAD);

    // usage columns (hidden on first run)
    if app.phase == Phase::NeedsEnable {
        ui.painter().text(Pos2::new(cols.hits.0 + CELL_PAD, rect.center().y), Align2::LEFT_CENTER, "—  ·  —  ·  —", t::sans(11.0), t::FIRSTRUN_DASH());
    } else if let Some(st) = &apply_status {
        // apply status occupies the last-seen/apps span
        let (txt, col) = st.label(r);
        ui.painter().text(Pos2::new(cols.hits.0 + CELL_PAD, rect.center().y), Align2::LEFT_CENTER, hits_ab(r).0, t::mono(11.5), t::DISABLED());
        ui.painter().text(Pos2::new(cols.last.0 + CELL_PAD, rect.center().y), Align2::LEFT_CENTER, &txt, if matches!(st, RowApply::Active(_)) { t::mono_medium(11.0) } else { t::sans(11.0) }, col);
    } else {
        // hits A / B (with per-profile split on hover)
        let (a, b, azero, bnz) = hits_ab_parts(r);
        let hx = cols.hits.0 + CELL_PAD;
        let ga = ui.painter().layout_no_wrap(a.clone(), t::mono(11.5), if azero { t::DISABLED() } else { t::INK() });
        let wa = ga.size().x;
        ui.painter().galley(Pos2::new(hx, rect.center().y - ga.size().y / 2.0), ga, if azero { t::DISABLED() } else { t::INK() });
        ui.painter().text(Pos2::new(hx + wa + 4.0, rect.center().y), Align2::LEFT_CENTER, "/", t::mono(11.5), t::HAIRLINE_TEXT());
        ui.painter().text(Pos2::new(hx + wa + 12.0, rect.center().y), Align2::LEFT_CENTER, &b, t::mono(11.5), if bnz { t::BLOCK() } else { t::DISABLED() });
        if let Some(u) = &r.usage {
            if !u.by_profile.is_empty() {
                let hits_rect = col_rect(cols.hits, rect);
                if ui.rect_contains_pointer(hits_rect) {
                    egui::show_tooltip_at_pointer(ui.ctx(), ui.layer_id(), egui::Id::new(("hits_tt", ri)), |ui| {
                        ui.label(egui::RichText::new("Hits by profile (allow / block)").font(t::semibold(11.0)).color(t::INK()));
                        for (prof, al, bl) in &u.by_profile {
                            ui.label(egui::RichText::new(format!("{prof}:  {} / {}", t::fmt_thousands(*al), t::fmt_thousands(*bl))).font(t::mono(11.0)).color(t::SECONDARY()));
                        }
                    });
                }
            }
        }

        // last seen
        let (last_txt, last_col) = match r.usage.as_ref().and_then(|u| u.last_seen.as_deref()) {
            Some(ls) => (time_util::relative(ls), t::SECONDARY()),
            None => ("never".to_string(), t::DISABLED()),
        };
        cell_text(ui.painter(), col_rect(cols.last, rect), &last_txt, t::sans(11.0), last_col, CELL_PAD);

        // apps observed
        let apps = apps_summary(r);
        let (apps_txt, apps_col) = if apps.is_empty() { ("—".to_string(), t::HAIRLINE_TEXT()) } else { (apps, t::SECONDARY()) };
        cell_text(ui.painter(), Rect::from_min_size(Pos2::new(cols.apps.0, rect.top()), Vec2::new(cols.apps.1 - CELL_PAD, rect.height())), &apps_txt, t::sans(11.0), apps_col, CELL_PAD);

        // listening chip
        if let Some(first) = r.listening.first() {
            draw_listen_chip(ui.painter(), Pos2::new(cols.listen.0 + CELL_PAD, rect.center().y - 8.5), first);
        } else {
            ui.painter().text(Pos2::new(cols.listen.0 + CELL_PAD, rect.center().y), Align2::LEFT_CENTER, "—", t::sans(11.0), t::HAIRLINE_TEXT());
        }
    }

    // reviewed mark — a ROUND control, deliberately unlike the square
    // enable checkbox: ticking it attests "I've verified this rule",
    // it never changes the firewall
    use crate::ui::ReviewState;
    let rv_center = Pos2::new(cols.reviewed.0 + CELL_PAD + 10.0, rect.center().y);
    let rv_tip = match &r.reviewed {
        ReviewState::Yes(at) => {
            glyph::circle_check(ui.painter(), rv_center, true, t::ENABLE_GREEN(), Color32::WHITE);
            format!("Reviewed {at} — click to clear")
        }
        ReviewState::Stale(at) => {
            ui.painter().circle_stroke(rv_center, 7.0, Stroke::new(1.3, t::ADVISORY()));
            // exclamation: stem + dot
            ui.painter().line_segment(
                [Pos2::new(rv_center.x, rv_center.y - 3.6), Pos2::new(rv_center.x, rv_center.y + 0.8)],
                Stroke::new(1.5, t::ADVISORY()),
            );
            ui.painter().circle_filled(Pos2::new(rv_center.x, rv_center.y + 3.4), 0.9, t::ADVISORY());
            format!("Was reviewed {at}, but the rule definition has changed since — verify again and click to re-mark")
        }
        ReviewState::No => {
            ui.painter().circle_stroke(rv_center, 7.0, Stroke::new(1.3, t::CB_EMPTY_BORDER()));
            "Mark this rule as reviewed/verified (does not change the firewall)".to_string()
        }
    };
    let rv_resp = ui.interact(
        Rect::from_center_size(rv_center, Vec2::splat(15.0)).expand(4.0),
        ui.id().with(("rv", ri)),
        Sense::click(),
    );
    if rv_resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    rv_resp.clone().on_hover_text(rv_tip);

    // tooltip built while the immutable borrow is live, so mutations below
    // don't overlap it
    let tip = format!(
        "{}\n{}",
        r.rule.description.as_deref().filter(|d| !d.trim().is_empty()).unwrap_or("(no description)"),
        listeners::scope_summary(&r.rule)
    );

    // interactions
    if let Some(bit) = clicked_profile {
        let p = &mut app.rows[ri].target_profiles;
        match bit {
            0 => p.domain = !p.domain,
            1 => p.private = !p.private,
            _ => p.public = !p.public,
        }
    } else if cb_resp.clicked() && app.apply.is_none() {
        app.rows[ri].target_enabled = !app.rows[ri].target_enabled;
    } else if rv_resp.clicked() {
        app.toggle_reviewed(ri);
    } else if resp.clicked() {
        app.selected = if selected { None } else { Some(ri) };
    }
    if resp.hovered() {
        resp.on_hover_text(tip);
    }
}

enum RowApply {
    Queued,
    Pending,
    Active(bool),
    Done,
    Failed(String),
}

impl RowApply {
    fn label(&self, _r: &super::RuleRow) -> (String, Color32) {
        match self {
            RowApply::Queued => ("queued".into(), t::TERTIARY()),
            RowApply::Pending => ("pending".into(), t::TERTIARY()),
            RowApply::Active(target) => (if *target { "applying…".into() } else { "disabling…".into() }, t::ACCENT()),
            RowApply::Done => ("applied ✓".into(), t::LIVE_TEXT()),
            RowApply::Failed(e) => (format!("failed — {}", short_err(e)), t::DESTRUCTIVE()),
        }
    }
}

fn short_err(e: &str) -> String {
    let line = e.lines().next().unwrap_or(e);
    if line.len() > 60 { format!("{}…", &line[..60]) } else { line.to_string() }
}

fn col_rect(c: (f32, f32), row: Rect) -> Rect {
    Rect::from_min_size(Pos2::new(c.0, row.top()), Vec2::new(c.1, row.height()))
}

fn dir_short(d: &str) -> &str {
    if d.eq_ignore_ascii_case("inbound") { "In" } else if d.eq_ignore_ascii_case("outbound") { "Out" } else { d }
}
fn act_short(a: &str) -> &str {
    if a.eq_ignore_ascii_case("allow") { "Allow" } else if a.eq_ignore_ascii_case("block") { "Block" } else { a }
}

fn hits_ab(r: &super::RuleRow) -> (&'static str, &'static str) {
    let _ = r;
    ("", "")
}
fn hits_ab_parts(r: &super::RuleRow) -> (String, String, bool, bool) {
    match &r.usage {
        Some(u) => (
            t::fmt_thousands(u.allow_count),
            t::fmt_thousands(u.block_count),
            u.allow_count == 0,
            u.block_count > 0,
        ),
        None => ("0".into(), "0".into(), true, false),
    }
}

fn apps_summary(r: &super::RuleRow) -> String {
    if r.seen_apps.is_empty() {
        return String::new();
    }
    let short: Vec<&str> = r.seen_apps.iter().map(|s| s.split(" (").next().unwrap_or(s)).collect();
    if short.len() <= 2 {
        short.join(", ")
    } else {
        format!("{}, {} +{}", short[0], short[1], short.len() - 2)
    }
}

enum CbMark {
    Check,
    Dash,
    None,
}

/// `partial` = the rule stays enabled but its profile scope was narrowed —
/// drawn as an indeterminate dash, the standard tri-state affordance.
fn draw_checkbox(p: &egui::Painter, rect: Rect, saved_on: bool, pending: bool, target: bool, partial: bool) {
    let (border, fill, mark, mark_col) = if partial {
        (t::ACCENT(), t::TABLE_BG(), CbMark::Dash, t::ACCENT())
    } else if pending {
        if target {
            (t::ACCENT(), t::ACCENT(), CbMark::Check, Color32::WHITE)
        } else {
            (t::ACCENT(), t::TABLE_BG(), CbMark::None, t::INK())
        }
    } else if saved_on {
        (t::CB_SAVED_BORDER(), t::TABLE_BG(), CbMark::Check, t::INK())
    } else {
        (t::CB_EMPTY_BORDER(), t::TABLE_BG(), CbMark::None, t::INK())
    };
    p.rect(rect, 0.0, fill, Stroke::new(1.5, border));
    match mark {
        CbMark::Check => glyph::check(p, rect.center(), 9.0, mark_col),
        CbMark::Dash => {
            p.hline(rect.left() + 3.0..=rect.right() - 3.0, rect.center().y, Stroke::new(2.0, mark_col));
        }
        CbMark::None => {}
    }
}

fn draw_listen_chip(p: &egui::Painter, top_left: Pos2, text: &str) {
    let font = t::mono(10.5);
    let galley = p.layout_no_wrap(text.to_string(), font, t::LIVE_TEXT());
    let w = galley.size().x + 14.0 + 11.0;
    let rect = Rect::from_min_size(top_left, Vec2::new(w, 17.0));
    p.rect(rect, 0.0, t::LIVE_BG(), Stroke::new(1.0, t::LIVE_BORDER()));
    p.circle_filled(Pos2::new(rect.left() + 7.0, rect.center().y), 3.0, t::LIVE());
    p.galley(Pos2::new(rect.left() + 14.0, rect.center().y - galley.size().y / 2.0), galley, t::LIVE_TEXT());
}

fn empty_state(app: &mut App, ui: &mut egui::Ui) {
    let full = ui.max_rect();
    let area = Rect::from_min_max(Pos2::new(full.left(), full.top() + HEADER_H), full.max);
    let mut child = ui.child_ui(area, egui::Layout::top_down(egui::Align::Center), None);
    child.add_space(40.0);
    let mut msg = egui::text::LayoutJob::default();
    msg.halign = egui::Align::Center;
    msg.append("No rules match ", 0.0, fmt(t::sans(12.5), t::SECONDARY()));
    if !app.filter_text.is_empty() {
        msg.append(&format!("“{}” ", app.filter_text), 0.0, fmt(t::semibold(12.5), t::SECONDARY()));
    }
    msg.append("with the current filters.", 0.0, fmt(t::sans(12.5), t::SECONDARY()));
    child.label(msg);
    child.add_space(4.0);
    let hidden = app.rows.len();
    child.label(egui::RichText::new(format!("{hidden} rules hidden by the active filters.")).font(t::sans(11.5)).color(t::FAINT()));
    child.add_space(10.0);
    child.horizontal(|ui| {
        ui.add_space((ui.available_width() - 240.0).max(0.0) / 2.0);
        if flat_button(ui, "Clear text").clicked() {
            app.filter_text.clear();
        }
        ui.add_space(10.0);
        if flat_button(ui, "Clear all filters").clicked() {
            app.filter_text.clear();
            app.only_enabled = false;
            app.only_zero_hit = false;
            app.only_flagged = false;
            app.show_domain = true;
            app.show_private = true;
            app.show_public = true;
        }
    });
}

// ---- detail panel ----

fn detail_panel(app: &mut App, ctx: &egui::Context) {
    let Some(ri) = app.selected else { return };
    egui::SidePanel::right("detail")
        .exact_width(300.0)
        .resizable(false)
        .frame(egui::Frame::none().fill(t::RAISED()))
        .show(ctx, |ui| {
            ui.painter().vline(ui.max_rect().left(), ui.max_rect().y_range(), Stroke::new(1.0, t::BORDER()));
            let r = &app.rows[ri];
            egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
                ui.add_space(12.0);
                ui.horizontal_top(|ui| {
                    ui.add_space(14.0);
                    // close button first (reserved on the right), then the
                    // title wrapping in the remaining width
                    let avail = ui.available_width();
                    ui.allocate_ui_with_layout(Vec2::new(avail - 30.0, 0.0), egui::Layout::top_down(egui::Align::Min), |ui| {
                        ui.add(egui::Label::new(egui::RichText::new(&r.rule.display_name).font(t::semibold(13.0)).color(t::INK())).wrap());
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                        ui.add_space(14.0);
                        let (cr, resp) = ui.allocate_exact_size(Vec2::splat(16.0), Sense::click());
                        if resp.hovered() {
                            ui.painter().rect_filled(cr.expand(2.0), 0.0, t::HOVER_WASH());
                            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                        }
                        glyph::cross(ui.painter(), cr.center(), 11.0, if resp.hovered() { t::INK() } else { t::FAINT() });
                        if resp.clicked() {
                            app.selected = None;
                        }
                    });
                });
                if let Some(desc) = r.rule.description.as_deref().filter(|d| !d.trim().is_empty()) {
                    ui.add_space(6.0);
                    pad_label(ui, egui::RichText::new(desc).font(t::italic(11.5)).color(t::SECONDARY()));
                }
                ui.add_space(12.0);
                section_sep(ui);

                // advisory blocks
                for f in &r.flags {
                    advisory_block(ui, f);
                    section_sep(ui);
                }

                // key-value grid
                ui.add_space(10.0);
                kv(ui, "Rule ID", &r.rule.name, true);
                if let Some(g) = r.rule.group.as_deref().filter(|s| !s.is_empty()) {
                    kv(ui, "Group", g, false);
                }
                kv(ui, "Program", r.rule.program.as_deref().unwrap_or("Any"), true);
                if let Some(s) = r.rule.service.as_deref().filter(|s| !s.is_empty() && *s != "Any") {
                    kv(ui, "Service", s, true);
                }
                kv(
                    ui,
                    "Ports",
                    &format!(
                        "{} local {} · remote {}",
                        r.rule.protocol.as_deref().unwrap_or("Any"),
                        r.rule.local_port.as_deref().unwrap_or("any"),
                        r.rule.remote_port.as_deref().unwrap_or("any")
                    ),
                    true,
                );
                kv(ui, "Remote addr", r.rule.remote_address.as_deref().unwrap_or("any"), true);
                ui.add_space(10.0);
                section_sep(ui);

                // evidence
                ui.add_space(12.0);
                if let Some(u) = &r.usage {
                    let total = u.allow_count + u.block_count;
                    pad_label(ui, egui::RichText::new(format!("Evidence — {} connections", t::fmt_thousands(total))).font(t::semibold(11.5)).color(t::INK()));
                    // per-profile split
                    if !u.by_profile.is_empty() {
                        ui.add_space(6.0);
                        for (prof, al, bl) in &u.by_profile {
                            let color = match prof.as_str() {
                                "Domain" => t::CHIP_DOM().1,
                                "Private" => t::CHIP_PRV().1,
                                "Public" => t::CHIP_PUB().1,
                                _ => t::TERTIARY(),
                            };
                            ui.horizontal(|ui| {
                                ui.add_space(14.0);
                                ui.label(egui::RichText::new(prof).font(t::semibold(11.0)).color(color));
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    ui.add_space(14.0);
                                    ui.label(egui::RichText::new(format!("{} / {}", t::fmt_thousands(*al), t::fmt_thousands(*bl))).font(t::mono(11.0)).color(t::SECONDARY()));
                                });
                            });
                        }
                    }
                    ui.add_space(8.0);
                    for (path, hits) in u.apps.iter().take(8) {
                        ui.horizontal(|ui| {
                            ui.add_space(14.0);
                            let name = crate::app_identity::identify(path).friendly_name;
                            ui.label(egui::RichText::new(name).font(t::sans(11.0)).color(t::INK()));
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.add_space(14.0);
                                ui.label(egui::RichText::new(t::fmt_thousands(*hits)).font(t::mono(11.0)).color(t::SECONDARY()));
                            });
                        });
                    }
                    ui.add_space(10.0);
                    let first = u.first_seen.as_deref().map(time_util::relative).unwrap_or_else(|| "—".into());
                    let last = u.last_seen.as_deref().map(time_util::relative).unwrap_or_else(|| "—".into());
                    pad_label(
                        ui,
                        egui::RichText::new(format!("First hit {first} · last {last} · {} distinct peers", u.distinct_peers))
                            .font(t::sans(11.0))
                            .color(t::SECONDARY()),
                    );
                } else {
                    pad_label(ui, egui::RichText::new("No usage evidence collected yet.").font(t::italic(11.5)).color(t::FAINT()));
                }
                ui.add_space(14.0);
            });
        });
}

fn pad_label(ui: &mut egui::Ui, text: egui::RichText) {
    ui.horizontal_top(|ui| {
        ui.add_space(14.0);
        let w = (ui.available_width() - 14.0).max(80.0); // leave 14 on the right
        ui.allocate_ui_with_layout(Vec2::new(w, 0.0), egui::Layout::top_down(egui::Align::Min), |ui| {
            ui.add(egui::Label::new(text).wrap());
        });
    });
}

fn section_sep(ui: &mut egui::Ui) {
    ui.add_space(2.0);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 1.0), Sense::hover());
    ui.painter().hline(rect.x_range(), rect.center().y, Stroke::new(1.0, t::BORDER_LIGHT()));
}

fn advisory_block(ui: &mut egui::Ui, f: &crate::model::BaselineFlag) {
    egui::Frame::none()
        .fill(t::ADVISORY_BG())
        .inner_margin(egui::Margin { left: 14.0, right: 14.0, top: 10.0, bottom: 10.0 })
        .show(ui, |ui| {
            ui.set_width(272.0);
            ui.horizontal(|ui| {
                let (r, _) = ui.allocate_exact_size(Vec2::new(12.0, 12.0), Sense::hover());
                glyph::warn_tri(ui.painter(), r.center(), 9.0, t::ADVISORY());
                ui.label(egui::RichText::new(f.title).font(t::semibold(11.0)).color(t::ADVISORY_TEXT()));
            });
            ui.add_space(3.0);
            ui.label(egui::RichText::new(f.advice).font(t::sans(11.0)).color(t::ADVISORY_TEXT()));
        });
}

fn kv(ui: &mut egui::Ui, label: &str, value: &str, mono: bool) {
    ui.horizontal_top(|ui| {
        ui.add_space(14.0);
        ui.allocate_ui_with_layout(Vec2::new(86.0, 0.0), egui::Layout::top_down(egui::Align::Min), |ui| {
            ui.label(egui::RichText::new(label).font(t::sans(11.0)).color(t::FAINT()));
        });
        ui.allocate_ui_with_layout(Vec2::new(184.0, 0.0), egui::Layout::top_down(egui::Align::Min), |ui| {
            let rt = if mono {
                egui::RichText::new(value).font(t::mono(10.5)).color(t::INK())
            } else {
                egui::RichText::new(value).font(t::sans(11.0)).color(t::INK())
            };
            ui.add(egui::Label::new(rt).wrap());
        });
    });
    ui.add_space(7.0);
}

// ---- evidence drawer ----

fn drawer(app: &mut App, ctx: &egui::Context) {
    if app.rows.is_empty() {
        return;
    }
    // Height fully owned by app.drawer_height (persists across frames); a
    // manual grab handle on the top edge adjusts it — no egui panel-memory
    // to fight, so it never snaps back.
    let panel_h = if app.drawer_open {
        app.drawer_height.clamp(90.0, 560.0) + 6.0 // +6 for the grab strip
    } else {
        28.0
    };
    egui::TopBottomPanel::bottom("drawer")
        .exact_height(panel_h)
        .resizable(false)
        .frame(egui::Frame::none().fill(t::RAISED()))
        .show(ctx, |ui| {
            // resize grab strip (only when open)
            if app.drawer_open {
                let (grip, gresp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 6.0), Sense::drag());
                if gresp.hovered() || gresp.dragged() {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeVertical);
                    ui.painter().hline(grip.x_range(), grip.center().y, Stroke::new(2.0, t::ACCENT_TINT_BORDER()));
                } else {
                    ui.painter().hline(grip.x_range(), grip.center().y, Stroke::new(1.0, t::BORDER_LIGHT()));
                }
                if gresp.dragged() {
                    // dragging up (negative dy) grows the drawer
                    app.drawer_height = (app.drawer_height - gresp.drag_delta().y).clamp(90.0, 560.0);
                }
            }

            // tab bar
            let bar = ui.allocate_exact_size(Vec2::new(ui.available_width(), 27.0), Sense::hover()).0;
            ui.painter().hline(bar.x_range(), bar.bottom() - 0.5, Stroke::new(1.0, t::BORDER_LIGHT()));
            let mut x = bar.left();
            let n_actions = app.applicable_action_count();
            let tabs = [
                (Tab::Sockets, format!("Active listening sockets  {}", app.listeners.len()), false),
                (Tab::Unattributed, format!("Unattributed events  {}", app.unmatched.len()), false),
                (Tab::Actions, format!("Bonus actions  {n_actions}"), n_actions > 0),
            ];
            for (tab, label, hot) in tabs {
                let active = app.drawer_open && app.tab == tab;
                // the Actions tab carries the flame while it has work to offer
                let idle_col = if hot { t::ACCENT() } else { t::SECONDARY() };
                let g = ui.painter().layout_no_wrap(label.clone(), if active { t::semibold(11.5) } else { t::sans(11.5) }, if active { t::INK() } else { idle_col });
                let w = g.size().x + 28.0;
                let tab_rect = Rect::from_min_size(Pos2::new(x, bar.top()), Vec2::new(w, 27.0));
                let hovered = ui.rect_contains_pointer(tab_rect);
                if active {
                    ui.painter().rect_filled(tab_rect, 0.0, t::TABLE_BG());
                    ui.painter().hline(tab_rect.x_range(), tab_rect.top() + 1.0, Stroke::new(2.0, t::ACCENT()));
                } else if hovered {
                    ui.painter().rect_filled(tab_rect, 0.0, t::HOVER_WASH());
                }
                ui.painter().vline(tab_rect.right(), tab_rect.y_range(), Stroke::new(1.0, t::BORDER_LIGHT()));
                ui.painter().galley(tab_rect.center() - g.size() / 2.0, g, if active { t::INK() } else { idle_col });
                let resp = ui.interact(tab_rect, ui.id().with(("tab", label)), Sense::click());
                if resp.hovered() {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                }
                if resp.clicked() {
                    if app.drawer_open && app.tab == tab {
                        app.drawer_open = false;
                    } else {
                        app.drawer_open = true;
                        app.tab = tab;
                    }
                }
                x += w;
            }

            // collapse / expand control — a real button with hover
            let label = if app.drawer_open { "collapse" } else { "expand" };
            let lg = ui.painter().layout_no_wrap(label.to_string(), t::sans(11.0), t::SECONDARY());
            let ctrl_w = lg.size().x + 26.0;
            let ctrl = Rect::from_min_size(Pos2::new(bar.right() - ctrl_w, bar.top()), Vec2::new(ctrl_w, 27.0));
            let cresp = ui.interact(ctrl, ui.id().with("drawer_toggle"), Sense::click());
            let ccol = if cresp.hovered() { t::INK() } else { t::SECONDARY() };
            if cresp.hovered() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                ui.painter().rect_filled(ctrl, 0.0, t::HOVER_WASH());
            }
            if app.drawer_open {
                glyph::tri_down(ui.painter(), Pos2::new(ctrl.left() + 9.0, bar.center().y), 8.0, ccol);
            } else {
                glyph::tri_up(ui.painter(), Pos2::new(ctrl.left() + 9.0, bar.center().y), 8.0, ccol);
            }
            ui.painter().text(Pos2::new(ctrl.left() + 18.0, bar.center().y), Align2::LEFT_CENTER, label, t::sans(11.0), ccol);
            if cresp.clicked() {
                app.drawer_open = !app.drawer_open;
            }

            if app.drawer_open {
                let h = ui.available_height().max(40.0);
                ui.allocate_ui(Vec2::new(ui.available_width(), h), |ui| match app.tab {
                    Tab::Sockets => sockets_body(app, ui),
                    Tab::Unattributed => unattributed_body(app, ui),
                    Tab::Actions => actions_body(app, ui),
                });
            }
        });
}

/// Bonus/quick actions: curated bulk operations, phrased as questions. A
/// stage button edits intended state only — the footer's confirm + backup +
/// Apply pipeline stays the single path to the firewall.
fn actions_body(app: &mut App, ui: &mut egui::Ui) {
    let rect = ui.max_rect();
    ui.painter().rect_filled(rect, 0.0, t::TABLE_BG());
    let mut child = ui.child_ui(rect.shrink2(Vec2::new(0.0, 4.0)), egui::Layout::top_down(egui::Align::Min), None);
    egui::ScrollArea::vertical().auto_shrink([false; 2]).show(&mut child, |ui| {
        let mut stage: Option<usize> = None;
        for (i, a) in crate::ui::actions_catalog().iter().enumerate() {
            let pending = app.action_pending(a);
            let n = pending.len();
            let row_h = 58.0;
            let (rr, _) = ui.allocate_exact_size(Vec2::new(rect.width(), row_h), Sense::hover());
            let p = ui.painter();
            let evidence_gated = a.needs_evidence && !app.ctx_info.auditing_active;

            // title + explanation (wrapped to leave room for the control)
            let text_w = (rr.width() - PAGE * 2.0 - 190.0).max(200.0);
            let title_col = if n > 0 { t::INK() } else { t::DISABLED() };
            p.text(Pos2::new(rr.left() + PAGE, rr.top() + 14.0), Align2::LEFT_CENTER, a.title, t::semibold(12.0), title_col);
            let explain = p.layout(a.explain.to_string(), t::sans(10.5), if n > 0 { t::SECONDARY() } else { t::DISABLED() }, text_w);
            p.galley(Pos2::new(rr.left() + PAGE, rr.top() + 26.0), explain, t::SECONDARY());

            // right-side control: count + stage button (or status text)
            let bx = rr.right() - PAGE - 160.0;
            if evidence_gated {
                p.text(Pos2::new(bx, rr.center().y), Align2::LEFT_CENTER, "needs auditing evidence", t::italic(11.0), t::DISABLED());
            } else if n == 0 {
                p.text(Pos2::new(bx, rr.center().y), Align2::LEFT_CENTER, "nothing to change", t::italic(11.0), t::DISABLED());
            } else {
                let label = match a.effect {
                    crate::ui::ActionEffect::Disable => format!("Stage: disable {n} rule{}", if n == 1 { "" } else { "s" }),
                    crate::ui::ActionEffect::RemovePublic => format!("Stage: edit {n} rule{}", if n == 1 { "" } else { "s" }),
                };
                let g = ui.painter().layout_no_wrap(label.clone(), t::sans(11.5), t::ACCENT());
                let brect = Rect::from_min_size(
                    Pos2::new(rr.right() - PAGE - g.size().x - 20.0, rr.center().y - 12.0),
                    Vec2::new(g.size().x + 20.0, 24.0),
                );
                let bresp = ui.interact(brect, ui.id().with(("act", i)), Sense::click());
                let (fill, border, txt) = if bresp.hovered() {
                    (t::ACCENT(), t::ACCENT(), t::TABLE_BG())
                } else {
                    (t::ACCENT_TINT(), t::ACCENT_TINT_BORDER(), t::ACCENT())
                };
                ui.painter().rect(brect, 0.0, fill, Stroke::new(1.0, border));
                ui.painter().galley(brect.center() - g.size() / 2.0, ui.painter().layout_no_wrap(label, t::sans(11.5), txt), txt);
                if bresp.hovered() {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                    bresp.clone().on_hover_text("Stages the change into the checkboxes/chips — nothing is applied until you review and click Apply (a policy backup is always written first).");
                }
                if bresp.clicked() {
                    stage = Some(i);
                }
            }
            ui.painter().hline(rr.x_range(), rr.bottom() - 0.5, Stroke::new(1.0, t::ROW_BORDER()));
        }
        if let Some(i) = stage {
            let a = &crate::ui::actions_catalog()[i];
            app.stage_action(a);
        }
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.add_space(PAGE);
            ui.label(egui::RichText::new("Staging only edits intent — review the pending footer, then Apply. Revert all undoes staged changes.").font(t::italic(10.5)).color(t::TERTIARY()));
        });
    });
}

fn sockets_body(app: &App, ui: &mut egui::Ui) {
    let rect = ui.max_rect();
    ui.painter().rect_filled(rect, 0.0, t::TABLE_BG());
    // header
    let hr = Rect::from_min_size(rect.min, Vec2::new(rect.width(), 22.0));
    let p = ui.painter();
    let hf = t::semibold(10.5);
    p.text(Pos2::new(rect.left() + PAGE, hr.center().y), Align2::LEFT_CENTER, "Proto", hf.clone(), t::FAINT());
    p.text(Pos2::new(rect.left() + PAGE + 60.0, hr.center().y), Align2::LEFT_CENTER, "Local address", hf.clone(), t::FAINT());
    p.text(Pos2::new(rect.left() + PAGE + 260.0, hr.center().y), Align2::LEFT_CENTER, "Process", hf.clone(), t::FAINT());
    p.text(Pos2::new(rect.left() + PAGE + 520.0, hr.center().y), Align2::LEFT_CENTER, "Matched rule", hf, t::FAINT());
    p.hline(rect.x_range(), hr.bottom(), Stroke::new(1.0, t::ROW_BORDER()));

    let mut list: Vec<&Listener> = app.listeners.iter().collect();
    list.sort_by_key(|l| (l.proto.clone(), l.local_port));
    let inner = Rect::from_min_max(Pos2::new(rect.left(), hr.bottom()), rect.max);
    let mut child = ui.child_ui(inner, egui::Layout::top_down(egui::Align::Min), None);
    egui::ScrollArea::vertical().auto_shrink([false; 2]).show(&mut child, |ui| {
        for l in list {
            let (rr, _) = ui.allocate_exact_size(Vec2::new(rect.width(), 20.0), Sense::hover());
            let p = ui.painter();
            let y = rr.center().y;
            p.text(Pos2::new(rect.left() + PAGE, y), Align2::LEFT_CENTER, &l.proto, t::mono(11.0), t::INK());
            p.text(Pos2::new(rect.left() + PAGE + 60.0, y), Align2::LEFT_CENTER, format!("{}:{}", l.local_address, l.local_port), t::mono(11.0), t::INK());
            let proc = if l.process_name.is_empty() { format!("pid {}", l.pid) } else { format!("{} (pid {})", l.process_name, l.pid) };
            p.text(Pos2::new(rect.left() + PAGE + 260.0, y), Align2::LEFT_CENTER, proc, t::mono(11.0), t::INK());
            let matched = matched_rule(app, l);
            let (txt, col) = match matched {
                Some(name) => (name, t::INK()),
                None if l.local_address.starts_with("127.") || l.local_address == "::1" => ("loopback — no rule required".to_string(), t::DISABLED()),
                None => ("—".to_string(), t::HAIRLINE_TEXT()),
            };
            p.text(Pos2::new(rect.left() + PAGE + 520.0, y), Align2::LEFT_CENTER, txt, t::sans(11.0), col);
            p.hline(rect.x_range(), rr.bottom() - 0.5, Stroke::new(1.0, t::CHROME()));
        }
    });
}

fn matched_rule(app: &App, l: &Listener) -> Option<String> {
    let key = format!("{}:{}", if l.process_name.is_empty() { format!("pid{}", l.pid) } else { l.process_name.clone() }, l.local_port);
    app.rows
        .iter()
        .find(|r| r.rule.is_enabled() && r.listening.iter().any(|e| e == &key))
        .map(|r| r.rule.display_name.clone())
}

fn unattributed_body(app: &App, ui: &mut egui::Ui) {
    let rect = ui.max_rect();
    ui.painter().rect_filled(rect, 0.0, t::TABLE_BG());
    // permanent explainer
    let ex = Rect::from_min_size(rect.min, Vec2::new(rect.width(), 26.0));
    ui.painter().rect_filled(ex, 0.0, t::RAISED());
    ui.painter().hline(ex.x_range(), ex.bottom(), Stroke::new(1.0, t::ROW_BORDER()));
    let mut job = egui::text::LayoutJob::default();
    job.wrap.max_width = rect.width() - 2.0 * PAGE;
    job.append("Traffic that Windows blocked by default policy — it matched no rule at all. Port scans and stray broadcasts land here. This is normal, not an error.", 0.0, fmt(t::italic(11.0), t::SECONDARY()));
    ui.painter().galley(Pos2::new(rect.left() + PAGE, ex.center().y - 7.0), ui.painter().layout_job(job), t::SECONDARY());

    let inner = Rect::from_min_max(Pos2::new(rect.left(), ex.bottom()), rect.max);
    let mut child = ui.child_ui(inner, egui::Layout::top_down(egui::Align::Min), None);
    if app.unmatched.is_empty() {
        child.centered_and_justified(|ui| {
            ui.label(egui::RichText::new("Nothing yet — unattributed events appear once auditing is enabled.").font(t::sans(11.5)).color(t::CB_EMPTY_BORDER()));
        });
        return;
    }
    egui::ScrollArea::vertical().auto_shrink([false; 2]).show(&mut child, |ui| {
        for u in app.unmatched.iter().take(100) {
            let (rr, _) = ui.allocate_exact_size(Vec2::new(rect.width(), 20.0), Sense::hover());
            let p = ui.painter();
            let y = rr.center().y;
            p.text(Pos2::new(rect.left() + PAGE, y), Align2::LEFT_CENTER, &u.filter_name, t::sans(11.0), t::INK());
            p.text(Pos2::new(rect.left() + PAGE + 470.0, y), Align2::LEFT_CENTER, format!("{} allow / {} block", u.usage.allow_count, u.usage.block_count), t::mono(10.5), t::SECONDARY());
            p.hline(rect.x_range(), rr.bottom() - 0.5, Stroke::new(1.0, t::CHROME()));
        }
    });
}

// ---- footer ----

fn footer(app: &mut App, ctx: &egui::Context) {
    let (dis, en, scope) = app.pending_counts();
    let has_pending = dis + en + scope > 0;
    let running = app.apply_running();
    let partial = app.apply_partial_failure();
    if !has_pending && !running && !partial {
        return;
    }
    let (fill, border) = if partial {
        (t::FAIL_BG(), t::FAIL_BORDER())
    } else {
        (t::ACCENT_TINT(), t::ACCENT_TINT_BORDER())
    };
    egui::TopBottomPanel::bottom("footer")
        .exact_height(44.0)
        .frame(egui::Frame::none().fill(fill).inner_margin(egui::Margin::symmetric(PAGE, 0.0)))
        .show(ctx, |ui| {
            ui.painter().hline(ui.max_rect().expand2(Vec2::new(PAGE, 0.0)).x_range(), ui.max_rect().top(), Stroke::new(1.0, border));
            if running {
                footer_running(app, ui);
            } else if partial {
                footer_partial(app, ui);
            } else {
                footer_pending(app, ui, dis, en, scope, ctx);
            }
        });
}

fn footer_pending(app: &mut App, ui: &mut egui::Ui, dis: usize, en: usize, scope: usize, ctx: &egui::Context) {
    ui.horizontal_centered(|ui| {
        let total = dis + en + scope;
        let mut job = egui::text::LayoutJob::default();
        job.append(&format!("{total} pending change{}", if total == 1 { "" } else { "s" }), 0.0, fmt(t::semibold(12.0), t::INK()));
        job.append("  —  ", 0.0, fmt(t::sans(12.0), t::SECONDARY()));
        let mut parts: Vec<(String, egui::Color32)> = Vec::new();
        if dis > 0 { parts.push((format!("{dis} to disable"), t::BLOCK())); }
        if en > 0 { parts.push((format!("{en} to enable"), t::ENABLE_GREEN())); }
        if scope > 0 { parts.push((format!("{scope} profile change{}", if scope == 1 { "" } else { "s" }), t::ACCENT())); }
        for (i, (text, col)) in parts.iter().enumerate() {
            if i > 0 {
                job.append(" · ", 0.0, fmt(t::sans(12.0), t::SECONDARY()));
            }
            job.append(text, 0.0, fmt(t::sans(12.0), *col));
        }
        ui.label(job);
        ui.add_space(14.0);
        if link(ui, "Revert all", t::ACCENT()).clicked() {
            app.revert_all();
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if app.read_only_session() {
                // reviewing imported data — Apply would hit THIS host, not the
                // reviewed one, so it's disabled
                ui.label(egui::RichText::new("Read-only review — apply changes on the device itself.").font(t::italic(11.0)).color(t::SECONDARY()));
            } else {
                let label = format!("Apply {total} change{}…", if total == 1 { "" } else { "s" });
                if primary_button(ui, &label, t::ACCENT()).clicked() {
                    app.confirm_open = true;
                }
                ui.add_space(14.0);
                ui.label(egui::RichText::new("A restorable policy backup is written before any change.").font(t::italic(11.0)).color(t::SECONDARY()));
            }
        });
    });
    let _ = ctx;
}

fn footer_running(app: &mut App, ui: &mut egui::Ui) {
    let (total, done, current, backup, backup_failed) = {
        let a = app.apply.as_ref().unwrap();
        (a.total, a.done, a.current.clone(), a.backup.clone(), a.backup_failed.clone())
    };
    let cur_name = current
        .as_ref()
        .and_then(|cur| app.rows.iter().find(|r| &r.rule.name == cur).map(|r| r.rule.display_name.clone()))
        .or_else(|| current.clone())
        .unwrap_or_default();
    ui.horizontal_centered(|ui| {
        let (track, _) = ui.allocate_exact_size(Vec2::new(200.0, 6.0), Sense::hover());
        ui.painter().rect_filled(track, 0.0, t::PROGRESS_TRACK());
        let frac = if total > 0 { done as f32 / total as f32 } else { 0.0 };
        ui.painter().rect_filled(Rect::from_min_size(track.min, Vec2::new(track.width() * frac, track.height())), 0.0, t::ACCENT());
        ui.add_space(14.0);
        let step = (done + if current.is_some() { 1 } else { 0 }).min(total).max(1);
        let mut job = egui::text::LayoutJob::default();
        job.append(&format!("Applying {step} of {total} "), 0.0, fmt(t::semibold(12.0), t::INK()));
        if !cur_name.is_empty() {
            job.append(&format!("— {cur_name}"), 0.0, fmt(t::sans(12.0), t::INK()));
        }
        ui.label(job);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if flat_button(ui, "Stop after current").clicked() {
                if let Some(a) = &mut app.apply {
                    a.stop_requested = true;
                }
            }
            ui.add_space(14.0);
            if let Some(b) = &backup {
                ui.label(egui::RichText::new(format!("Backup written ✓  {}", b.rsplit(['\\', '/']).next().unwrap_or(b))).font(t::sans(11.0)).color(t::SECONDARY()));
            } else if let Some(e) = &backup_failed {
                ui.label(egui::RichText::new(format!("Backup failed: {}", short_err(e))).font(t::sans(11.0)).color(t::DESTRUCTIVE()));
            }
        });
    });
}

fn footer_partial(app: &mut App, ui: &mut egui::Ui) {
    let (ok, fail) = {
        let a = app.apply.as_ref().unwrap();
        (a.results.values().filter(|r| r.is_ok()).count(), a.results.values().filter(|r| r.is_err()).count())
    };
    ui.horizontal_centered(|ui| {
        let mut job = egui::text::LayoutJob::default();
        job.append(&format!("{ok} of {} applied.", ok + fail), 0.0, fmt(t::semibold(12.0), t::DESTRUCTIVE_DARK()));
        job.append(&format!(" {fail} failed and {} still pending — nothing was rolled back.", if fail == 1 { "is" } else { "are" }), 0.0, fmt(t::sans(12.0), t::DESTRUCTIVE_DARK()));
        ui.label(job);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if primary_button(ui, &format!("Retry {fail} failed"), t::ACCENT()).clicked() {
                let ctx = ui.ctx().clone();
                app.apply = None;
                app.start_apply(&ctx);
            }
            ui.add_space(8.0);
            if flat_button(ui, "Dismiss").clicked() {
                // revert intent on failed rows back to saved, clear apply
                if let Some(a) = app.apply.take() {
                    for (name, res) in a.results {
                        if res.is_err() {
                            if let Some(r) = app.rows.iter_mut().find(|r| r.rule.name == name) {
                                r.target_enabled = r.rule.is_enabled();
                            }
                        }
                    }
                }
            }
            ui.add_space(14.0);
            ui.label(egui::RichText::new("Backup retained.").font(t::italic(11.0)).color(t::SECONDARY()));
        });
    });
}

fn primary_button(ui: &mut egui::Ui, label: &str, fill: Color32) -> egui::Response {
    let galley = ui.painter().layout_no_wrap(label.to_string(), t::semibold(12.0), Color32::WHITE);
    let size = Vec2::new(galley.size().x + 36.0, galley.size().y + 14.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let f = if resp.is_pointer_button_down_on() {
        fill.gamma_multiply(0.85)
    } else if resp.hovered() {
        fill.gamma_multiply(1.12)
    } else {
        fill
    };
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    ui.painter().rect_filled(rect, 0.0, f);
    ui.painter().galley(rect.center() - galley.size() / 2.0, galley, Color32::WHITE);
    resp
}

// ---- confirm modal ----

fn confirm_modal(app: &mut App, ctx: &egui::Context) {
    let plan = app.planned_changes();
    let total = plan.len();
    let (dis, en, scope) = app.pending_counts();
    // scrim
    egui::Area::new("scrim".into()).order(egui::Order::Background).show(ctx, |ui| {
        let r = ctx.screen_rect();
        ui.painter().rect_filled(r, 0.0, Color32::from_rgba_unmultiplied(28, 28, 30, 102));
    });
    let mut open = true;
    // list gets up to ~55% of the window height before it scrolls
    let list_max = (ctx.screen_rect().height() * 0.55).clamp(200.0, 520.0);
    egui::Window::new("confirm")
        .title_bar(false)
        .collapsible(false)
        .resizable(false)
        .fixed_size(Vec2::new(680.0, 0.0))
        .anchor(Align2::CENTER_TOP, Vec2::new(0.0, 70.0))
        .frame(egui::Frame::none().fill(t::TABLE_BG()).stroke(Stroke::new(1.0, t::CONTROL_BORDER())))
        .show(ctx, |ui| {
            // title
            ui.add_space(16.0);
            pad20(ui, |ui| {
                ui.label(egui::RichText::new(format!("Apply {total} change{} to Windows Firewall?", if total == 1 { "" } else { "s" })).font(t::semibold(15.0)).color(t::INK()));
                ui.add_space(4.0);
                ui.label(egui::RichText::new(format!("{} · policy will change immediately for new connections", app.ctx_info.hostname)).font(t::sans(12.0)).color(t::SECONDARY()));
            });
            ui.add_space(12.0);
            section_sep(ui);
            ui.add_space(12.0);

            // change rows (scrollable — a big batch shouldn't blow the modal)
            pad20(ui, |ui| {
                egui::ScrollArea::vertical()
                    .max_height(list_max)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        for c in &plan {
                            change_row(app, ui, c);
                        }
                    });
            });

            // backup box
            ui.add_space(12.0);
            pad20(ui, |ui| {
                egui::Frame::none()
                    .fill(t::BACKUP_BG())
                    .stroke(Stroke::new(1.0, t::BACKUP_BORDER()))
                    .inner_margin(egui::Margin::symmetric(12.0, 10.0))
                    .show(ui, |ui| {
                        ui.horizontal_top(|ui| {
                            ui.spacing_mut().item_spacing.x = 8.0;
                            let (r, _) = ui.allocate_exact_size(Vec2::new(13.0, 14.0), Sense::hover());
                            glyph::check(ui.painter(), r.center(), 11.0, t::LIVE_TEXT());
                            let mut job = egui::text::LayoutJob::default();
                            job.wrap.max_width = 500.0;
                            job.append("A restorable backup of the full firewall policy is written ", 0.0, fmt(t::sans(11.5), t::BACKUP_TEXT()));
                            job.append("before", 0.0, fmt(t::semibold(11.5), t::BACKUP_TEXT()));
                            job.append(" any change, to ", 0.0, fmt(t::sans(11.5), t::BACKUP_TEXT()));
                            job.append("%ProgramData%\\firebreak\\backups\\", 0.0, fmt(t::mono(10.5), t::BACKUP_TEXT()));
                            job.append(" — restore anytime from Settings → Backups.", 0.0, fmt(t::sans(11.5), t::BACKUP_TEXT()));
                            ui.label(job);
                        });
                    });
            });
            ui.add_space(12.0);
            section_sep(ui);

            // footer buttons
            ui.add_space(12.0);
            pad20(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Changes are also written to the audit log.").font(t::sans(11.0)).color(t::FAINT()));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let mut bits = Vec::new();
                        if dis > 0 { bits.push(format!("disable {dis}")); }
                        if en > 0 { bits.push(format!("enable {en}")); }
                        if scope > 0 { bits.push(format!("rescope {scope}")); }
                        let verb = format!("Back up & {}", bits.join(", "));
                        if primary_button(ui, &verb, t::DESTRUCTIVE()).clicked() {
                            app.confirm_open = false;
                            open = false;
                            app.start_apply(ctx);
                        }
                        ui.add_space(10.0);
                        if flat_button(ui, "Cancel").clicked() {
                            app.confirm_open = false;
                            open = false;
                        }
                    });
                });
            });
            ui.add_space(14.0);
        });
    if !open {
        app.confirm_open = false;
    }
}

fn change_row(app: &App, ui: &mut egui::Ui, c: &super::PlannedChange) {
    use super::ChangeKind;
    let r = app.rows.iter().find(|r| r.rule.name == c.name);
    let (verb, vc, bg, reason) = match &c.kind {
        ChangeKind::Disable => (
            "DISABLE",
            t::BLOCK(),
            t::VERB_DISABLE_BG(),
            r.map(|r| disable_reason(r)).unwrap_or_default(),
        ),
        ChangeKind::Enable => (
            "ENABLE",
            t::ENABLE_GREEN(),
            t::BACKUP_BG(),
            "currently disabled — will begin allowing this traffic".to_string(),
        ),
        ChangeKind::Profiles { arg, removed, .. } => (
            "RESCOPE",
            t::ACCENT(),
            t::ACCENT_TINT(),
            format!("remove {removed} — rule stays active on {}", arg.replace(',', ", ")),
        ),
    };
    egui::Frame::none()
        .fill(bg)
        .inner_margin(egui::Margin::symmetric(10.0, 8.0))
        .show(ui, |ui| {
            ui.horizontal_top(|ui| {
                ui.allocate_ui_with_layout(Vec2::new(64.0, 0.0), egui::Layout::top_down(egui::Align::Min), |ui| {
                    ui.label(egui::RichText::new(verb).font(t::semibold(11.0)).color(vc));
                });
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 1.0;
                    ui.label(egui::RichText::new(&c.display).font(t::semibold(12.5)).color(t::INK()));
                    ui.label(egui::RichText::new(reason).font(t::sans(11.0)).color(t::TERTIARY()));
                });
            });
        });
    ui.add_space(1.0);
}

fn disable_reason(r: &super::RuleRow) -> String {
    let hits = r.total_hits();
    let flag = r.flags.first().map(|f| format!(" · flagged: {}", f.title)).unwrap_or_default();
    let listen = if r.listening.is_empty() { " · not listening" } else { "" };
    format!("{hits} hits in the audit window{listen}{flag}")
}

fn pad20(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        ui.add_space(20.0);
        ui.vertical(|ui| {
            ui.set_max_width(560.0);
            add(ui);
        });
        ui.add_space(20.0);
    });
}
