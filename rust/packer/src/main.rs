//! EXELock packer GUI 入口。

// 隐藏控制台窗口（GUI 子系统）。必须在 crate 根部、所有其他项之前。
#![windows_subsystem = "windows"]

use exelock_packer::app::AppModel;
use eframe::egui;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([640.0, 560.0])
            .with_min_inner_size([560.0, 480.0])
            .with_title("EXELock"),
        ..Default::default()
    };
    eframe::run_native(
        "EXELock",
        options,
        Box::new(|cc| {
            setup_cjk_fonts(&cc.egui_ctx);
            Ok(Box::new(AppModel::new()))
        }),
    )
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
