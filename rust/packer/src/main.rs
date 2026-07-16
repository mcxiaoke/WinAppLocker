//! EXELock packer GUI 入口。

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
        Box::new(|_cc| Ok(Box::new(AppModel::new()))),
    )
}
