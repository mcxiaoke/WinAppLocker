//! egui GUI 界面。
//!
//! 即时模式：每帧根据 `AppModel` 状态重绘。加密在后台线程执行，
//! 通过 `crossbeam-channel` 把进度与结果回传给 UI 线程。

use std::path::PathBuf;
use std::sync::Arc;

use crossbeam_channel::{Receiver, Sender};
use eframe::egui;

use crate::pack::{pack, PackError, PackOptions, PackReport, ProgressFn};
use crate::strength::{algorithm_name, algorithm_options, kdf_name, kdf_options, StrengthSpec};
use crate::stub_selector::{StubPreference, StubKind, check_stub_available};
use crate::version;

/// 后台线程 → UI 线程的消息。
enum WorkerMsg {
    Progress(f32),
    Done(Result<PackReport, PackError>),
}

/// UI 状态。
pub struct AppModel {
    input_path: String,
    output_path: String,
    password: String,
    confirm_password: String,
    // 高级选项（与 StrengthSpec 同步）
    algorithm_id: u16,
    kdf_id: u16,
    kdf_iterations: u32,
    salt_len: u16,
    use_aad: bool,
    erase_payload: bool,
    stub_pref: StubPreference,
    // 运行状态
    working: bool,
    progress: f32,
    last_report: Option<Arc<Result<PackReport, PackError>>>,
    // 后台通信
    worker_tx: Option<Sender<WorkerMsg>>,
    worker_rx: Option<Receiver<WorkerMsg>>,
    // stub 状态缓存（启动时检测一次）
    stub_status: StubStatus,
    show_password: bool,
}

#[derive(Clone)]
enum StubStatus {
    Checked {
        gui_ok: bool,
        console_ok: bool,
        gui_version: Option<String>,
        console_version: Option<String>,
    },
    NotChecked,
}

impl Default for AppModel {
    fn default() -> Self {
        // 默认使用 Balanced 预设参数（预设选择已从 UI 移除）。
        let spec = StrengthSpec::balanced();
        Self {
            input_path: String::new(),
            output_path: String::new(),
            password: String::new(),
            confirm_password: String::new(),
            algorithm_id: spec.algorithm_id,
            kdf_id: spec.kdf_id,
            kdf_iterations: spec.kdf_iterations,
            salt_len: 16,
            use_aad: spec.use_aad,
            erase_payload: spec.erase_payload,
            stub_pref: StubPreference::Auto,
            working: false,
            progress: 0.0,
            last_report: None,
            worker_tx: None,
            worker_rx: None,
            stub_status: StubStatus::NotChecked,
            show_password: false,
        }
    }
}

impl AppModel {
    pub fn new() -> Self {
        let mut model = Self::default();
        model.check_stubs();
        model
    }

    /// 启动时检测 stub 目录状态。
    fn check_stubs(&mut self) {
        let gui_ok = check_stub_available(StubKind::Gui).is_ok();
        let console_ok = check_stub_available(StubKind::Console).is_ok();
        let gui_version = if gui_ok {
            version::load_stub_version(StubKind::Gui)
                .map(|v| format!("{}", v))
        } else {
            None
        };
        let console_version = if console_ok {
            version::load_stub_version(StubKind::Console)
                .map(|v| format!("{}", v))
        } else {
            None
        };
        self.stub_status = StubStatus::Checked {
            gui_ok,
            console_ok,
            gui_version,
            console_version,
        };
    }

    /// 构造 PackOptions（从 UI 字段）。
    fn build_options(&self) -> PackOptions {
        PackOptions {
            input_path: PathBuf::from(&self.input_path),
            output_path: PathBuf::from(&self.output_path),
            password: self.password.clone(),
            algorithm_id: self.algorithm_id,
            kdf_id: self.kdf_id,
            kdf_iterations: self.kdf_iterations,
            salt_len: self.salt_len,
            use_aad: self.use_aad,
            erase_payload: self.erase_payload,
            stub_preference: self.stub_pref.clone(),
            custom_extensions: Vec::new(),
        }
    }

    /// 校验输入，返回错误消息（None 表示可加密）。
    fn validate(&self) -> Option<String> {
        if self.input_path.trim().is_empty() {
            return Some("请选择待处理的EXE文件".into());
        }
        if !std::path::Path::new(&self.input_path).exists() {
            return Some("你选择的EXE文件不存在".into());
        }
        if self.output_path.trim().is_empty() {
            return Some("请选择输出路径".into());
        }
        if self.password.is_empty() {
            return Some("密码不能为空".into());
        }
        if self.password.len() < 4 {
            return Some("密码至少 4 个字符".into());
        }
        if self.password != self.confirm_password {
            return Some("两次输入的密码不一致".into());
        }
        None
    }

    /// stub 是否可用（至少有一个 stub 可加载）。
    fn stubs_available(&self) -> bool {
        match &self.stub_status {
            StubStatus::Checked { gui_ok, console_ok, .. } => *gui_ok || *console_ok,
            StubStatus::NotChecked => false,
        }
    }

    /// 启动后台加密线程。
    fn start_pack(&mut self) {
        let opts = self.build_options();
        let (tx, rx) = crossbeam_channel::unbounded();
        self.worker_tx = Some(tx.clone());
        self.worker_rx = Some(rx);
        self.working = true;
        self.progress = 0.0;
        self.last_report = None;

        std::thread::spawn(move || {
            let tx2 = tx.clone();
            let progress_fn: ProgressFn = Box::new(move |frac: f32| {
                let _ = tx2.send(WorkerMsg::Progress(frac));
            });
            let result = pack(&opts, Some(progress_fn));
            let _ = tx.send(WorkerMsg::Done(result));
        });
    }

    /// 每帧调用：处理后台消息。
    fn poll_worker(&mut self) {
        let rx = match self.worker_rx.take() {
            Some(rx) => rx,
            None => return,
        };
        let mut done_msg = None;
        while let Ok(msg) = rx.try_recv() {
            match msg {
                WorkerMsg::Progress(f) => self.progress = f,
                WorkerMsg::Done(r) => {
                    done_msg = Some(r);
                    break;
                }
            }
        }
        if let Some(r) = done_msg {
            self.working = false;
            self.progress = if r.is_ok() { 1.0 } else { 0.0 };
            self.last_report = Some(Arc::new(r));
            self.worker_tx = None;
        } else {
            self.worker_rx = Some(rx);
        }
    }
}

const HEADING_COLOR: egui::Color32 = egui::Color32::from_rgb(0x2D, 0x7D, 0xB3);
const ACCENT_COLOR: egui::Color32 = egui::Color32::from_rgb(0x20, 0x90, 0x20);
const ERROR_COLOR: egui::Color32 = egui::Color32::from_rgb(0xC0, 0x20, 0x20);
const WARN_COLOR: egui::Color32 = egui::Color32::from_rgb(0xC0, 0x60, 0x20);
const MUTED_COLOR: egui::Color32 = egui::Color32::from_rgb(0x88, 0x88, 0x88);

impl eframe::App for AppModel {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker();
        if self.working {
            ctx.request_repaint();
        }

        // ===== 底部版本信息面板 =====
        egui::TopBottomPanel::bottom("version_panel")
            .resizable(false)
            .show_separator_line(false)
            .show(ctx, |ui| {
                ui.add_space(6.0);
                // ui.separator();
                ui.add_space(4.0);
                self.render_version_info(ui);
                ui.add_space(4.0);
            });

        // ===== 主内容面板 =====
        egui::CentralPanel::default().show(ctx, |ui| {
            // 行间距加大一点，整体看起来更舒服
            ui.spacing_mut().item_spacing.y = 6.0;
            ui.add_space(8.0);

            // ===== 文件选择 =====
            ui.horizontal(|ui| {
                ui.label("文件路径:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.input_path).desired_width(380.0),
                );
                if ui.button("浏览…").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("可执行文件", &["exe"])
                        .pick_file()
                    {
                        self.input_path = path.display().to_string();
                        let mut out = path.clone();
                        let stem = out.file_stem().and_then(|s| s.to_str()).unwrap_or("out");
                        out.set_file_name(format!("{}_locked.exe", stem));
                        self.output_path = out.display().to_string();
                    }
                }
            });

            ui.horizontal(|ui| {
                ui.label("输出路径:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.output_path).desired_width(380.0),
                );
                if ui.button("浏览…").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("可执行文件", &["exe"])
                        .set_file_name("locked.exe")
                        .save_file()
                    {
                        self.output_path = path.display().to_string();
                    }
                }
            });

            ui.add_space(8.0);

            // ===== 密码 =====
            ui.horizontal(|ui| {
                ui.label("输入密码:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.password)
                        .desired_width(280.0)
                        .password(!self.show_password),
                );
                if ui.button(if self.show_password { "🙈" } else { "👁" }).clicked() {
                    self.show_password = !self.show_password;
                }
            });
            ui.horizontal(|ui| {
                ui.label("确认密码:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.confirm_password)
                        .desired_width(280.0)
                        .password(!self.show_password),
                );
            });

            ui.add_space(8.0);

            // ===== 进度条 =====
            if self.working || self.progress > 0.0 {
                ui.add(
                    egui::ProgressBar::new(self.progress)
                        .text(format!("{:.0}%", self.progress * 100.0)),
                );
            }

            // ===== 结果消息 =====
            if let Some(report) = &self.last_report {
                ui.add_space(4.0);
                match report.as_ref() {
                    Ok(r) => {
                        ui.colored_label(
                            ACCENT_COLOR,
                            format!(
                                "加密成功：{} → {}（{}KB → {}KB，{}，{} 迭代）",
                                basename(&self.input_path),
                                basename(&self.output_path),
                                r.original_size / 1024,
                                r.output_size / 1024,
                                algorithm_name(r.algorithm_id),
                                r.kdf_iterations
                            ),
                        );
                    }
                    Err(e) => {
                        ui.colored_label(ERROR_COLOR, format!("✗ 加密失败：{}", e));
                    }
                }
            }

            ui.add_space(8.0);

            // ===== 按钮 =====
            ui.horizontal(|ui| {
                if self.working {
                    ui.add_enabled(false, egui::Button::new("加密中…"));
                } else {
                    let can_pack = self.validate().is_none() && self.stubs_available();
                    let btn = egui::Button::new("加密锁定");
                    if ui.add_enabled(can_pack, btn).clicked() {
                        self.start_pack();
                    }
                    if !self.stubs_available() {
                        ui.colored_label(ERROR_COLOR, "stub 未就绪，请检查 stub 目录");
                    } else if let Some(err) = self.validate() {
                        ui.colored_label(WARN_COLOR, err);
                    }
                }
            });

            ui.add_space(8.0);
            ui.label(
                egui::RichText::new("提示：加密后的 EXE 需放在原目录运行，输入密码后启动原程序。")
                    .small()
                    .color(MUTED_COLOR),
            );
        });
    }
}

impl AppModel {
    /// stub 状态行：放在主面板里，只显示是否可用，不再显示版本（版本在底部面板）。
    fn render_stub_status(&self, ui: &mut egui::Ui) {
        match &self.stub_status {
            StubStatus::NotChecked => {}
            StubStatus::Checked { gui_ok, console_ok, .. } => {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Stub:").small().color(MUTED_COLOR));

                    let gui_text = if *gui_ok { "✓ gui" } else { "✗ gui" };
                    let console_text = if *console_ok { "✓ console" } else { "✗ console" };
                    let gui_color = if *gui_ok { ACCENT_COLOR } else { ERROR_COLOR };
                    let console_color = if *console_ok { ACCENT_COLOR } else { ERROR_COLOR };

                    ui.label(egui::RichText::new(gui_text).small().color(gui_color));
                    ui.label(egui::RichText::new("|").small().color(MUTED_COLOR));
                    ui.label(egui::RichText::new(console_text).small().color(console_color));
                });
            }
        }
    }

    /// 版本信息：放在界面底部，分行显示 packer / stub 的版本。
    fn render_version_info(&self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            // ---- packer ----
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!(
                        "WinAppLocker v{}",
                        version::PACKER_VERSION
                    ))
                    .size(11.0)
                    .color(MUTED_COLOR),
                );
            });
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!(
                        "git: {}    build: {}",
                        version::PACKER_GIT_HASH,
                        version::PACKER_BUILD_TIME
                    ))
                    .size(11.0)
                    .color(MUTED_COLOR),
                );
            });

            // ---- stub ----
            if let StubStatus::Checked { gui_ok, console_ok, gui_version, console_version } =
                &self.stub_status
            {
                ui.add_space(2.0);
                if *gui_ok {
                    let v = gui_version.as_deref().unwrap_or("v?");
                    ui.label(
                        egui::RichText::new(format!("Stub GUI    {}", v))
                            .size(11.0)
                            .color(MUTED_COLOR),
                    );
                }
                if *console_ok {
                    let v = console_version.as_deref().unwrap_or("v?");
                    ui.label(
                        egui::RichText::new(format!("Stub Console    {}", v))
                            .size(11.0)
                            .color(MUTED_COLOR),
                    );
                }
            }
        });
    }
}

fn stub_pref_label(p: &StubPreference) -> &'static str {
    match p {
        StubPreference::Auto => "Auto（自动）",
        StubPreference::Gui => "GUI",
        StubPreference::Console => "Console",
        StubPreference::Custom(_) => "Custom（自定义）",
    }
}

fn basename(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
        .unwrap_or_default()
}
