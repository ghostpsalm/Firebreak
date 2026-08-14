//! Design tokens (light + dark) and embedded IBM Plex fonts. Colors are
//! runtime-switchable functions rather than consts so the whole custom-
//! painted UI can flip between light and dark. Names are kept UPPER_CASE so
//! call sites read like the original const palette (`t::ACCENT()`).
#![allow(non_snake_case)]

use eframe::egui::{self, Color32, FontFamily, FontId};
use std::cell::Cell;

thread_local! {
    static DARK: Cell<bool> = const { Cell::new(false) };
}

pub fn set_dark(dark: bool) {
    DARK.with(|d| d.set(dark));
}
pub fn is_dark() -> bool {
    DARK.with(|d| d.get())
}

/// Pick the light or dark value for the current mode.
#[inline]
fn c(light: (u8, u8, u8), dark: (u8, u8, u8)) -> Color32 {
    let (r, g, b) = if is_dark() { dark } else { light };
    Color32::from_rgb(r, g, b)
}

// ---- semantic palette: "Char & Flame" (light, dark) ----
// Five source colors: Gogh Red CC0000 · Char 1C1C1E · Smoke 55565A ·
// Ash A9ABAF · Bone F4F2EF. Red is the only brand chroma — it marks
// consequence (pending changes, destructive verbs, blocks, public
// exposure). Everything else is charred neutral derived from Char/Ash/
// Bone. Green/amber survive purely as functional status colors.
pub fn ACCENT() -> Color32 {
    c((0xCC, 0x00, 0x00), (0xE8, 0x56, 0x4A))
}
pub fn ACCENT_TINT() -> Color32 {
    c((0xFC, 0xED, 0xEA), (0x3A, 0x21, 0x1E))
}
pub fn ACCENT_TINT_BORDER() -> Color32 {
    c((0xF2, 0xC9, 0xC0), (0x5E, 0x2D, 0x26))
}
pub fn SELECTED_ROW() -> Color32 {
    c((0xED, 0xEA, 0xE5), (0x2A, 0x2A, 0x2E))
}
pub fn DESTRUCTIVE() -> Color32 {
    c((0xCC, 0x00, 0x00), (0xE5, 0x4B, 0x3C))
}
pub fn DESTRUCTIVE_DARK() -> Color32 {
    c((0x9E, 0x00, 0x00), (0xC2, 0x3B, 0x2E))
}
pub fn FAIL_BG() -> Color32 {
    c((0xFB, 0xED, 0xEA), (0x3A, 0x23, 0x20))
}
pub fn FAIL_BORDER() -> Color32 {
    c((0xE8, 0xBD, 0xB4), (0x6E, 0x3E, 0x38))
}
pub fn BLOCK() -> Color32 {
    c((0xB5, 0x15, 0x08), (0xE0, 0x6B, 0x5E))
}
pub fn LIVE() -> Color32 {
    c((0x2E, 0x9E, 0x5B), (0x3B, 0xC4, 0x74))
}
pub fn LIVE_TEXT() -> Color32 {
    c((0x23, 0x7A, 0x46), (0x62, 0xD9, 0x93))
}
pub fn LIVE_BG() -> Color32 {
    c((0xEA, 0xF7, 0xEF), (0x14, 0x2E, 0x1E))
}
pub fn LIVE_BORDER() -> Color32 {
    c((0xC5, 0xE8, 0xD2), (0x2E, 0x5C, 0x3F))
}
pub fn ADVISORY() -> Color32 {
    c((0xB7, 0x95, 0x0B), (0xE0, 0xB9, 0x3A))
}
pub fn ADVISORY_BG() -> Color32 {
    c((0xFD, 0xF6, 0xDE), (0x31, 0x2C, 0x13))
}
pub fn ADVISORY_BORDER() -> Color32 {
    c((0xEB, 0xD9, 0x8A), (0x5C, 0x4E, 0x1E))
}
pub fn ADVISORY_TEXT() -> Color32 {
    c((0x7D, 0x66, 0x08), (0xE8, 0xC8, 0x60))
}
pub fn ADVISORY_HEADER() -> Color32 {
    c((0x9A, 0x7D, 0x0A), (0xD4, 0xB4, 0x40))
}

pub fn INK() -> Color32 {
    c((0x1C, 0x1C, 0x1E), (0xE9, 0xE7, 0xE4))
}
pub fn SECONDARY() -> Color32 {
    c((0x55, 0x56, 0x5A), (0xB6, 0xB4, 0xB0))
}
pub fn TERTIARY() -> Color32 {
    c((0x77, 0x78, 0x7D), (0x96, 0x97, 0x9B))
}
pub fn FAINT() -> Color32 {
    c((0x8E, 0x8F, 0x94), (0x7F, 0x80, 0x85))
}
pub fn DISABLED() -> Color32 {
    c((0xAD, 0xAE, 0xB3), (0x5E, 0x5F, 0x64))
}
pub fn HAIRLINE_TEXT() -> Color32 {
    c((0xC9, 0xC8, 0xC4), (0x4A, 0x4B, 0x50))
}

pub fn CHROME() -> Color32 {
    c((0xF4, 0xF2, 0xEF), (0x20, 0x20, 0x23))
}
pub fn TABLE_BG() -> Color32 {
    c((0xFF, 0xFF, 0xFF), (0x25, 0x25, 0x28))
}
pub fn RAISED() -> Color32 {
    c((0xFA, 0xF9, 0xF7), (0x2B, 0x2B, 0x2F))
}
/// The dialogs' footer action bar — a shade off the dialog body, so the
/// action row reads as a separate register from the content above it.
pub fn DIALOG_FOOTER() -> Color32 {
    c((0xF7, 0xF7, 0xF5), (0x1F, 0x1F, 0x22))
}
pub fn TITLEBAR() -> Color32 {
    c((0xEC, 0xEA, 0xE6), (0x1C, 0x1C, 0x1E))
}
pub fn BORDER() -> Color32 {
    c((0xD6, 0xD4, 0xCF), (0x3E, 0x3F, 0x44))
}
pub fn BORDER_LIGHT() -> Color32 {
    c((0xE4, 0xE2, 0xDD), (0x33, 0x34, 0x38))
}
pub fn ROW_BORDER() -> Color32 {
    c((0xF0, 0xEE, 0xEA), (0x2E, 0x2F, 0x33))
}
pub fn CONTROL_BORDER() -> Color32 {
    c((0xC7, 0xC5, 0xC0), (0x4A, 0x4B, 0x51))
}
pub fn DARK_SEGMENT() -> Color32 {
    c((0x2C, 0x2C, 0x30), (0x56, 0x57, 0x5D))
}
pub fn HOVER_WASH() -> Color32 {
    c((0xF7, 0xF5, 0xF1), (0x2A, 0x2A, 0x2E))
}
pub fn ENABLE_GREEN() -> Color32 {
    c((0x23, 0x7A, 0x46), (0x62, 0xD9, 0x93))
}
pub fn BACKUP_BG() -> Color32 {
    c((0xF0, 0xF8, 0xF2), (0x14, 0x2E, 0x1E))
}
pub fn BACKUP_BORDER() -> Color32 {
    c((0xC8, 0xE4, 0xCE), (0x2E, 0x5C, 0x3F))
}
pub fn BACKUP_TEXT() -> Color32 {
    c((0x19, 0x6F, 0x3D), (0x7D, 0xDB, 0xA0))
}
pub fn VERB_DISABLE_BG() -> Color32 {
    c((0xFB, 0xF2, 0xEF), (0x3A, 0x23, 0x20))
}
pub fn CB_SAVED_BORDER() -> Color32 {
    c((0x7A, 0x7B, 0x80), (0x8E, 0x8F, 0x94))
}
pub fn CB_EMPTY_BORDER() -> Color32 {
    c((0xBE, 0xBD, 0xB8), (0x5E, 0x5F, 0x65))
}
pub fn PROGRESS_TRACK() -> Color32 {
    c((0xF5, 0xD9, 0xD4), (0x4A, 0x2B, 0x27))
}
pub fn FIRSTRUN_DASH() -> Color32 {
    c((0xD6, 0xD4, 0xCF), (0x4A, 0x4B, 0x51))
}

// profile chips: (label, fg, bg, border)
// Domain/Private are quiet charred neutrals; PUBLIC is the one red chip —
// the public profile is the exposed surface, so it carries the flame.
pub fn CHIP_DOM() -> (&'static str, Color32, Color32, Color32) {
    (
        "DOM",
        c((0x3A, 0x3B, 0x40), (0xC6, 0xC7, 0xCB)),
        c((0xEC, 0xEB, 0xE7), (0x30, 0x30, 0x34)),
        c((0xCE, 0xCD, 0xC8), (0x4A, 0x4B, 0x50)),
    )
}
pub fn CHIP_PRV() -> (&'static str, Color32, Color32, Color32) {
    (
        "PRV",
        c((0x6E, 0x6F, 0x74), (0x9E, 0x9F, 0xA4)),
        c((0xF3, 0xF2, 0xEF), (0x2A, 0x2A, 0x2E)),
        c((0xDC, 0xDA, 0xD5), (0x40, 0x41, 0x46)),
    )
}
pub fn CHIP_PUB() -> (&'static str, Color32, Color32, Color32) {
    (
        "PUB",
        c((0xB5, 0x15, 0x08), (0xE8, 0x77, 0x6B)),
        c((0xFB, 0xED, 0xEA), (0x3A, 0x21, 0x1E)),
        c((0xEF, 0xC7, 0xBF), (0x5E, 0x2D, 0x26)),
    )
}
pub fn CHIP_ANY() -> (&'static str, Color32, Color32, Color32) {
    (
        "ANY",
        c((0x85, 0x86, 0x8B), (0x96, 0x97, 0x9B)),
        c((0xF0, 0xEF, 0xEC), (0x2C, 0x2C, 0x30)),
        c((0xD8, 0xD6, 0xD1), (0x46, 0x47, 0x4C)),
    )
}

// ---- fonts ----

const SANS: &str = "plex-sans";
const SANS_MEDIUM: &str = "plex-sans-medium";
const SANS_SEMIBOLD: &str = "plex-sans-semibold";
const SANS_ITALIC: &str = "plex-sans-italic";
const MONO: &str = "plex-mono";
const MONO_MEDIUM: &str = "plex-mono-medium";

pub fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let faces: [(&str, &[u8]); 6] = [
        (
            SANS,
            include_bytes!("../assets/fonts/IBMPlexSans-Regular.ttf"),
        ),
        (
            SANS_MEDIUM,
            include_bytes!("../assets/fonts/IBMPlexSans-Medium.ttf"),
        ),
        (
            SANS_SEMIBOLD,
            include_bytes!("../assets/fonts/IBMPlexSans-SemiBold.ttf"),
        ),
        (
            SANS_ITALIC,
            include_bytes!("../assets/fonts/IBMPlexSans-Italic.ttf"),
        ),
        (
            MONO,
            include_bytes!("../assets/fonts/IBMPlexMono-Regular.ttf"),
        ),
        (
            MONO_MEDIUM,
            include_bytes!("../assets/fonts/IBMPlexMono-Medium.ttf"),
        ),
    ];
    for (name, bytes) in faces {
        fonts
            .font_data
            .insert(name.to_string(), egui::FontData::from_static(bytes));
    }
    let default_stack: Vec<String> = fonts
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    for name in [
        SANS,
        SANS_MEDIUM,
        SANS_SEMIBOLD,
        SANS_ITALIC,
        MONO,
        MONO_MEDIUM,
    ] {
        let mut stack = vec![name.to_string()];
        stack.extend(default_stack.iter().cloned());
        fonts.families.insert(FontFamily::Name(name.into()), stack);
    }
    fonts
        .families
        .get_mut(&FontFamily::Proportional)
        .unwrap()
        .insert(0, SANS.to_string());
    fonts
        .families
        .get_mut(&FontFamily::Monospace)
        .unwrap()
        .insert(0, MONO.to_string());
    ctx.set_fonts(fonts);
}

pub fn sans(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(SANS.into()))
}
pub fn medium(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(SANS_MEDIUM.into()))
}
pub fn semibold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(SANS_SEMIBOLD.into()))
}
pub fn italic(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(SANS_ITALIC.into()))
}
pub fn mono(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(MONO.into()))
}
pub fn mono_medium(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(MONO_MEDIUM.into()))
}

/// (Re)apply egui visuals for the current mode. Call after set_dark.
pub fn apply_visuals(ctx: &egui::Context) {
    let mut visuals = if is_dark() {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    visuals.panel_fill = CHROME();
    visuals.window_fill = TABLE_BG();
    visuals.extreme_bg_color = TABLE_BG();
    visuals.faint_bg_color = RAISED();
    visuals.selection.bg_fill = ACCENT().gamma_multiply(0.35);
    visuals.hyperlink_color = ACCENT();
    visuals.override_text_color = Some(INK());
    for w in [
        &mut visuals.widgets.noninteractive,
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        w.rounding = egui::Rounding::ZERO;
        w.bg_fill = TABLE_BG();
        w.weak_bg_fill = RAISED();
        w.fg_stroke.color = INK();
    }
    visuals.widgets.noninteractive.fg_stroke.color = SECONDARY();
    visuals.window_rounding = egui::Rounding::ZERO;
    visuals.menu_rounding = egui::Rounding::ZERO;
    visuals.window_shadow = egui::epaint::Shadow {
        offset: egui::vec2(0.0, 12.0),
        blur: 40.0,
        spread: 0.0,
        color: Color32::from_black_alpha(if is_dark() { 140 } else { 76 }),
    };
    visuals.popup_shadow = egui::epaint::Shadow {
        offset: egui::vec2(0.0, 4.0),
        blur: 12.0,
        spread: 0.0,
        color: Color32::from_black_alpha(if is_dark() { 120 } else { 40 }),
    };
    ctx.set_visuals(visuals);
}

pub fn apply_style(ctx: &egui::Context) {
    install_fonts(ctx);
    apply_visuals(ctx);
    ctx.style_mut(|s| {
        s.spacing.item_spacing = egui::vec2(8.0, 4.0);
        s.spacing.button_padding = egui::vec2(12.0, 5.0);
    });
}

/// "1,482,306"
pub fn fmt_thousands(n: i64) -> String {
    let s = n.abs().to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    if n < 0 {
        format!("-{out}")
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::fmt_thousands;

    #[test]
    fn thousands_formatting() {
        assert_eq!(fmt_thousands(0), "0");
        assert_eq!(fmt_thousands(999), "999");
        assert_eq!(fmt_thousands(1204), "1,204");
        assert_eq!(fmt_thousands(1_482_306), "1,482,306");
    }
}
