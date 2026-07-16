//! egui GUI 界面。
//!
//! 即时模式：每帧根据 `AppModel` 状态重绘。加密在后台线程执行，
//! 通过 `crossbeam-channel` 把进度与结果回传给 UI 线程。

use std::path::PathBuf;
use std::sync::Arc;

use crossbeam_channel::{Receiver, Sender};
use eframe::egui;

use crate::pack::{pack, PackError, PackOptions, PackReport, ProgressFn};
use crate::strength::{
    algorithm_name, algorithm_options, kdf_name, kdf_options, Strength, StrengthSpec,
};
use crate::stub_selector::StubPreference;

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
    strength: Strength,
    advanced_open: bool,
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
}

impl Default for AppModel {
    fn default() -> Self {
        let spec = StrengthSpec::for_strength(Strength::Balanced);
        Self {
            input_path: String::new(),
            output_path: String::new(),
            password: String::new(),
            confirm_password: String::new(),
            strength: Strength::Balanced,
            advanced_open: false,
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
        }
    }
}

impl AppModel {
    pub fn new() -> Self {
        Self::default()
    }

    /// 当前高级选项是否与某个预设一致。
    fn detect_strength(&self) -> Strength {
        for &s in Strength::all() {
            if matches!(s, Strength::Custom) {
                continue;
            }
            let spec = StrengthSpec::for_strength(s);
            if spec.algorithm_id == self.algorithm_id
                && spec.kdf_id == self.kdf_id
                && spec.kdf_iterations == self.kdf_iterations
                && spec.use_aad == self.use_aad
                && spec.erase_payload == self.erase_payload
            {
                return s;
            }
        }
        Strength::Custom
    }

    /// 切换预设时，同步高级选项字段。
    fn apply_strength(&mut self, s: Strength) {
        let spec = StrengthSpec::for_strength(s);
        self.algorithm_id = spec.algorithm_id;
        self.kdf_id = spec.kdf_id;
        self.kdf_iterations = spec.kdf_iterations;
        self.use_aad = spec.use_aad;
        self.erase_payload = spec.erase_payload;
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
            return Some("请选择原 EXE 文件".into());
        }
        if !std::path::Path::new(&self.input_path).exists() {
            return Some("原 EXE 文件不存在".into());
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
        // 先 take 出 rx 避免借用冲突
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
            // worker_rx 已经被 take，不用再置 None
        } else {
            // 还在工作中，把 rx 放回去
            self.worker_rx = Some(rx);
        }
    }
}

impl eframe::App for AppModel {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker();
        // 工作中持续请求重绘以更新进度
        if self.working {
            ctx.request_repaint();
        }

        // 自动根据高级选项检测预设
        if !self.working {
            let detected = self.detect_strength();
            if detected != self.strength {
                self.strength = detected;
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("EXELock — EXE 加密保护工具");
            ui.add_space(8.0);

            // ===== 文件选择 =====
            ui.horizontal(|ui| {
                ui.label("原 EXE:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.input_path).desired_width(400.0),
                );
                if ui.button("浏览…").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("可执行文件", &["exe"])
                        .pick_file()
                    {
                        self.input_path = path.display().to_string();
                        // 自动填充输出路径：原名_locked.exe（总是更新）
                        let mut out = path.clone();
                        let stem = out.file_stem().and_then(|s| s.to_str()).unwrap_or("out");
                        out.set_file_name(format!("{}_locked.exe", stem));
                        self.output_path = out.display().to_string();
                    }
                }
            });

            ui.horizontal(|ui| {
                ui.label("输出:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.output_path).desired_width(400.0),
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

            ui.add_space(6.0);

            // ===== 密码 =====
            ui.horizontal(|ui| {
                ui.label("密码:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.password)
                        .desired_width(300.0)
                        .password(true),
                );
            });
            ui.horizontal(|ui| {
                ui.label("确认:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.confirm_password)
                        .desired_width(300.0)
                        .password(true),
                );
            });

            ui.add_space(6.0);

            // ===== 强度预设 =====
            ui.horizontal(|ui| {
                ui.label("加密强度:");
                for &s in Strength::all() {
                    if ui.radio_value(&mut self.strength, s, s.label()).clicked() {
                        if !matches!(s, Strength::Custom) {
                            self.apply_strength(s);
                        }
                    }
                }
            });

            // ===== 高级选项（可折叠）=====
            ui.add_space(4.0);
            ui.collapsing("▶ 高级选项", |ui| {
                // 算法
                ui.horizontal(|ui| {
                    ui.label("算法:");
                    let current_name = algorithm_name(self.algorithm_id);
                    egui::ComboBox::from_id_salt("algo_combo")
                        .selected_text(current_name)
                        .show_ui(ui, |ui| {
                            for &(id, name) in algorithm_options() {
                                ui.selectable_value(&mut self.algorithm_id, id, name);
                            }
                        });
                });
                // KDF
                ui.horizontal(|ui| {
                    ui.label("KDF:");
                    let current_name = kdf_name(self.kdf_id);
                    egui::ComboBox::from_id_salt("kdf_combo")
                        .selected_text(current_name)
                        .show_ui(ui, |ui| {
                            for &(id, name) in kdf_options() {
                                ui.selectable_value(&mut self.kdf_id, id, name);
                            }
                        });
                });
                // 迭代次数
                ui.horizontal(|ui| {
                    ui.label("迭代次数:");
                    ui.add(
                        egui::DragValue::new(&mut self.kdf_iterations)
                            .range(100_000..=100_000_000u32)
                            .speed(1000.0),
                    );
                });
                // Salt 长度
                ui.horizontal(|ui| {
                    ui.label("Salt 长度:");
                    ui.add(
                        egui::DragValue::new(&mut self.salt_len)
                            .range(8..=64u16)
                            .speed(1.0),
                    );
                });
                // 复选框
                ui.checkbox(&mut self.use_aad, "启用 AAD（绑定 header，防篡改）");
                ui.checkbox(&mut self.erase_payload, "解密后擦除 payload");
                // Stub 选择
                ui.horizontal(|ui| {
                    ui.label("Stub:");
                    egui::ComboBox::from_id_salt("stub_combo")
                        .selected_text(stub_pref_label(&self.stub_pref))
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.stub_pref, StubPreference::Auto, "Auto（自动）");
                            ui.selectable_value(&mut self.stub_pref, StubPreference::Gui, "GUI");
                            ui.selectable_value(&mut self.stub_pref, StubPreference::Console, "Console");
                        });
                });
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new("（反调试 / 反 dump 为未来版本功能，当前未启用）")
                        .small()
                        .color(egui::Color32::GRAY),
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
                            egui::Color32::from_rgb(0x20, 0x90, 0x20),
                            format!(
                                "✓ 加密成功：{} → {}（{}KB → {}KB，{}，{} 迭代）",
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
                        ui.colored_label(
                            egui::Color32::from_rgb(0xC0, 0x20, 0x20),
                            format!("✗ 加密失败：{}", e),
                        );
                    }
                }
            }

            ui.add_space(8.0);

            // ===== 按钮 =====
            ui.horizontal(|ui| {
                if self.working {
                    ui.add_enabled(false, egui::Button::new("加密中…"));
                } else {
                    let can_pack = self.validate().is_none();
                    let btn = egui::Button::new("加密");
                    if ui.add_enabled(can_pack, btn).clicked() {
                        self.start_pack();
                    }
                    if let Some(err) = self.validate() {
                        ui.colored_label(egui::Color32::from_rgb(0xC0, 0x60, 0x20), err);
                    }
                }
            });

            ui.add_space(12.0);
            ui.label(
                egui::RichText::new("提示：生成的 locked 文件已包含完整 RunPE stub，可直接运行。")
                    .small()
                    .color(egui::Color32::from_rgb(0x60, 0x90, 0x60)),
            );
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
