//! WinAppLocker packer GUI 入口。

// 隐藏控制台窗口（GUI 子系统）。必须在 crate 根部、所有其他项之前。
#![windows_subsystem = "windows"]

use exelock_packer::app::AppModel;
use eframe::egui;
use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};

fn main() -> eframe::Result<()> {
    let win_w = 640.0_f32;
    let win_h = 480.0_f32;

    // 计算窗口居中位置（基于主屏幕工作区）
    let pos = center_pos(win_w, win_h);

    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([win_w, win_h])
        .with_min_inner_size([560.0, 400.0])
        .with_position(pos)
        .with_title("WinAppLocker - EXE加锁工具");

    if let Some(icon) = load_app_icon() {
        viewport = viewport.with_icon(icon);
    }

    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "WinAppLocker",
        options,
        Box::new(|cc| {
            setup_cjk_fonts(&cc.egui_ctx);
            Ok(Box::new(AppModel::new()))
        }),
    )
}

/// 加载并解码 packer 自身的图标（assets/app.ico）。
///
/// 返回 RGBA 像素数据，用于设置窗口标题栏 / 任务栏图标，
/// 使其与 exe 文件图标（由 winres 嵌入）保持一致。
fn load_app_icon() -> Option<egui::IconData> {
    let icon_bytes = include_bytes!("../assets/app.ico");
    let img = image::load_from_memory_with_format(icon_bytes, image::ImageFormat::Ico).ok()?;
    let rgba = img.to_rgba8();
    let (w, h) = rgba.dimensions();
    Some(egui::IconData {
        rgba: rgba.into_raw(),
        width: w,
        height: h,
    })
}

/// 计算窗口在主屏幕居中的位置。
fn center_pos(win_w: f32, win_h: f32) -> egui::Pos2 {
    unsafe {
        let sw = GetSystemMetrics(SM_CXSCREEN) as f32;
        let sh = GetSystemMetrics(SM_CYSCREEN) as f32;
        egui::Pos2::new(
            ((sw - win_w) / 2.0).max(0.0),
            ((sh - win_h) / 2.0).max(0.0),
        )
    }
}

/// 配置中文字体（egui 默认字体不含 CJK 字符，会显示方框）。
///
/// 从 Windows 系统字体目录加载 Microsoft YaHei（微软雅黑），
/// 作为 Proportional 和 Monospace 字体族的后备字体。
fn setup_cjk_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    // 尝试加载系统中文字体（优先微软雅黑，回退到宋体）
    let font_paths = [
        "C:\\Windows\\Fonts\\msyh.ttc",    // Microsoft YaHei
        "C:\\Windows\\Fonts\\msyh.ttf",    // Microsoft YaHei (old)
        "C:\\Windows\\Fonts\\simsun.ttc",  // SimSun
        "C:\\Windows\\Fonts\\simhei.ttf",  // SimHei
    ];

    for path in &font_paths {
        if let Ok(font_bytes) = std::fs::read(path) {
            fonts.font_data.insert(
                "cjk".to_string(),
                egui::FontData::from_owned(font_bytes).into(),
            );
            // 把 CJK 字体加到各字体族末尾作为后备
            if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
                family.push("cjk".to_string());
            }
            if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
                family.push("cjk".to_string());
            }
            break;
        }
    }

    ctx.set_fonts(fonts);
}
