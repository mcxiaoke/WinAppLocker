using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace WinAppLocker.Packer {
    public partial class MainForm : Form {
        /// <summary>ComboBox 中 stub 列表项（包装 StubManifest，null=自动）</summary>
        private sealed class StubListItem
        {
            public readonly StubManifest Manifest;
            public readonly string Label;
            public StubListItem(StubManifest manifest, string label)
            {
                Manifest = manifest;
                Label = label;
            }
            public override string ToString() => Label;
        }

        private List<StubManifest> _availableStubs;

        /// <summary>缓存最近一次解析的 PE 信息，避免每次切换 stub 都重读文件</summary>
        private PeInfo _lastPeInfo;
        /// <summary>缓存最近一次解析的 PE 文件路径（用于判断缓存是否还有效）</summary>
        private string _lastPePath;

        public MainForm() {
            InitializeComponent();
            // 在构造函数里加载图标（不放 Designer.cs，避免 VS 设计器报 "未找到方法 Form.LoadIcon"）
            try {
                var asm = System.Reflection.Assembly.GetExecutingAssembly();
                using (var stream = asm.GetManifestResourceStream("WinAppLocker.Packer.assets.app.ico")) {
                    if (stream != null)
                        this.Icon = new System.Drawing.Icon(stream);
                }
            } catch { }

            AppLogger.Info($"GUI 启动（日志目录: {AppLogger.LogDirectory ?? "(禁用)"}）");
        }

        private void MainForm_Load(object sender, EventArgs e) {
            // 第一行：packer 版本 + git hash + 构建时间
            lblPackerVersion.Text = $"Packer v{VersionInfo.Version}  |  git: {VersionInfo.GitHash}  |  build: {VersionInfo.BuildTime}";

            // 动态加载 stub 列表
            LoadStubList();

            // 后续行：每个 stub 一行，显示名称/版本/架构/可用性
            UpdateStubInfo();
        }

        /// <summary>从 stub/ 目录加载所有 .meta.json，填充 ComboBox</summary>
        private void LoadStubList()
        {
            string stubDir = StubLoader.FindStubDir();
            _availableStubs = StubRegistry.LoadAll(stubDir);

            cbStubPreference.Items.Clear();
            // 第一项：自动（按原 EXE 子系统选）
            cbStubPreference.Items.Add(new StubListItem(null,
                $"自动（按子系统选，共 {_availableStubs.Count} 个 stub 可用）"));
            // 后续项：每个可用 stub
            foreach (var s in _availableStubs)
            {
                string label = $"{s.Name} - {s.Description}";
                if (!s.IsAvailable)
                    label += " (缺失文件)";
                cbStubPreference.Items.Add(new StubListItem(s, label));
            }
            cbStubPreference.SelectedIndex = 0;

            AppLogger.Info($"已加载 stub 列表: 共 {_availableStubs.Count} 个（可用 {_availableStubs.Count(s => s.IsAvailable)}，缺失 {_availableStubs.Count(s => !s.IsAvailable)}），目录: {stubDir}");
        }

        /// <summary>
        /// 更新底部 stub 信息面板：每个 stub 一行，显示 名称/版本/架构/类型/可用性。
        /// 第一行（packer 版本）由 MainForm_Load 直接写入 lblPackerVersion。
        /// </summary>
        private void UpdateStubInfo()
        {
            if (_availableStubs == null || _availableStubs.Count == 0)
            {
                lblStubInfo.Text = $"[无可用 stub，请检查 stub/ 目录: {StubLoader.FindStubDir()}]";
                lblStubInfo.ForeColor = System.Drawing.Color.Red;
                return;
            }

            var lines = new List<string>();
            foreach (var s in _availableStubs)
            {
                // 架构支持：amd64→x64, i386→x86, 空表示任意架构
                string arch;
                if (s.SupportedMachines == null || s.SupportedMachines.Count == 0)
                    arch = "any";
                else
                    arch = string.Join("+", s.SupportedMachines.Select(m =>
                        m == "amd64" ? "x64" : m == "i386" ? "x86" : m));

                // 可用性标记
                string status = s.IsAvailable
                    ? "✓"
                    : $"✗ 缺失: {string.Join(",", s.MissingComponents)}";

                lines.Add($"  {s.Name}  v{s.Version}  [{arch}]  {s.KindStr}  {status}");
            }

            lblStubInfo.Text = string.Join("\n", lines);
            // 有缺失则整体用警告色，否则默认色
            bool anyMissing = _availableStubs.Any(s => !s.IsAvailable);
            lblStubInfo.ForeColor = anyMissing ? System.Drawing.Color.OrangeRed : System.Drawing.Color.DarkSlateGray;
        }

        private void btnBrowseInput_Click(object sender, EventArgs e) {
            using (var dlg = new OpenFileDialog()) {
                dlg.Title = "选择原 EXE";
                dlg.Filter = "可执行文件 (*.exe)|*.exe|所有文件 (*.*)|*.*";
                dlg.CheckFileExists = true;
                if (dlg.ShowDialog(this) == DialogResult.OK) {
                    txtInputPath.Text = dlg.FileName;
                    // 自动填充输出路径：原文件名_locked.exe 同目录
                    string dir = System.IO.Path.GetDirectoryName(dlg.FileName);
                    string name = System.IO.Path.GetFileNameWithoutExtension(dlg.FileName);
                    txtOutputPath.Text = System.IO.Path.Combine(dir, name + "_locked.exe");
                    // 解析 PE 信息并刷新 PE 信息行（含兼容性警告）和按钮状态
                    UpdatePeInfoLabel(dlg.FileName);
                    UpdatePackButton();
                }
            }
        }

        private void btnBrowseOutput_Click(object sender, EventArgs e) {
            using (var dlg = new SaveFileDialog()) {
                dlg.Title = "选择输出路径";
                dlg.Filter = "可执行文件 (*.exe)|*.exe";
                if (!string.IsNullOrEmpty(txtOutputPath.Text)) {
                    dlg.FileName = System.IO.Path.GetFileName(txtOutputPath.Text);
                    dlg.InitialDirectory = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(txtOutputPath.Text));
                }
                if (dlg.ShowDialog(this) == DialogResult.OK) {
                    txtOutputPath.Text = dlg.FileName;
                    UpdatePackButton();
                }
            }
        }

        private void btnTogglePassword_Click(object sender, EventArgs e) {
            bool showing = txtPassword.PasswordChar == '\0';
            txtPassword.PasswordChar = showing ? '*' : '\0';
            txtConfirm.PasswordChar = showing ? '*' : '\0';
            btnTogglePassword.Text = showing ? "隐藏" : "显示";
        }

        private void txt_TextChanged(object sender, EventArgs e) {
            UpdatePackButton();
        }

        /// <summary>
        /// 检查当前选中的 stub 与原 PE 的兼容性。
        /// 返回 (warningText, isBlocking)：
        ///   - warningText：要显示的红字提示（null 表示无警告）
        ///   - isBlocking：true 表示不兼容应禁用加密按钮
        ///
        /// 规则（参照 PackCore.Pack 的拒绝逻辑）：
        ///   - InplaceBuilder / ReflectiveBuilder：仅不支持 .NET（C builder 也只检查 .NET CLR）
        ///   - Tempfile：无限制（.NET / Console 都支持）
        /// </summary>
        private (string Warning, bool Blocking) GetStubCompatibilityWarning(StubKind kind, PeInfo peInfo)
        {
            if (peInfo == null) return (null, false);

            if (kind == StubKind.InplaceBuilder)
            {
                if (peInfo.IsDotNet)
                    return ("⚠ inplace 不支持 .NET 程序，请改用临时文件模式", true);
            }
            else if (kind == StubKind.ReflectiveBuilder)
            {
                if (peInfo.IsDotNet)
                    return ("⚠ reflective 不支持 .NET 程序（CLR 假设主模块由 OS loader 加载）", true);
            }
            return (null, false);
        }

        /// <summary>ComboBox 选中项变化时刷新 PE 信息行（含兼容性警告）和按钮状态</summary>
        private void cbStubPreference_SelectedIndexChanged(object sender, EventArgs e)
        {
            // stub 变化时，PE 信息行需要重算兼容性警告，按钮也需要重算启用状态
            UpdatePeInfoLabel(txtInputPath.Text);
            UpdatePackButton();
        }

        private void UpdatePackButton() {
            bool ready = !string.IsNullOrEmpty(txtInputPath.Text)
                && !string.IsNullOrEmpty(txtOutputPath.Text)
                && !string.IsNullOrEmpty(txtPassword.Text)
                && txtPassword.Text == txtConfirm.Text;

            // 检查当前选中 stub 与 PE 的兼容性，不兼容禁用按钮
            if (ready && _lastPeInfo != null)
            {
                var item = cbStubPreference.SelectedItem as StubListItem;
                if (item != null && item.Manifest != null)
                {
                    var (_, blocking) = GetStubCompatibilityWarning(item.Manifest.Kind, _lastPeInfo);
                    if (blocking) ready = false;
                }
                // 选中"自动"时不阻止（让 PackCore 自己按子系统选合适的 stub）
            }

            btnPack.Enabled = ready;
        }

        /// <summary>
        /// 选择输入 exe 后，把 PE 关键信息（架构/子系统/ASLR/DEP/TLS/签名/.NET/大小）
        /// 显示在 lblPeInfo 上，放在"执行加密操作"按钮上方。
        /// 同时根据当前选中的 stub 追加兼容性警告（红字），便于用户立刻发现不兼容组合。
        /// </summary>
        private void UpdatePeInfoLabel(string exePath)
        {
            // 路径空或文件不存在：清空，重置缓存
            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
            {
                _lastPeInfo = null;
                _lastPePath = null;
                lblPeInfo.Text = "";
                lblPeInfo.ForeColor = System.Drawing.Color.DarkSlateGray;
                return;
            }

            // 解析 PE（路径变化才重读文件，避免切换 stub 时重复 IO）
            PeInfo info = _lastPeInfo;
            if (!string.Equals(_lastPePath, exePath, StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    byte[] pe = File.ReadAllBytes(exePath);
                    info = PeReader.Parse(pe);
                    _lastPeInfo = info;
                    _lastPePath = exePath;
                }
                catch (Exception ex)
                {
                    _lastPeInfo = null;
                    _lastPePath = exePath;
                    lblPeInfo.Text = $"PE 信息读取失败: {ex.Message}";
                    lblPeInfo.ForeColor = System.Drawing.Color.Red;
                    AppLogger.Warn($"PE 信息读取失败: {exePath}  异常: {ex.Message}");
                    return;
                }
            }

            // 大小用 KB 显示
            double sizeKb = info.FileSize / 1024.0;
            string sizeStr = sizeKb >= 1024
                ? $"{sizeKb / 1024.0:F1}MB"
                : $"{sizeKb:F0}KB";

            // 格式：x64 | GUI | ASLR✓ DEP✓ CFG✗ HEVA✗ | TLS✗ Signed✗ Reloc✓ | .NET✗ | 523.0KB
            // 用 ✓/✗ 直观表示开关
            string text = string.Join(" | ",
                $"{info.MachineName}",
                $"{info.SubsystemName}",
                $"ASLR{(info.IsAslr ? "✓" : "✗")} DEP{(info.IsDep ? "✓" : "✗")} CFG{(info.IsCfg ? "✓" : "✗")} HEVA{(info.IsHighEntropyVA ? "✓" : "✗")}",
                $"TLS{(info.HasTls ? "✓" : "✗")} Signed{(info.IsSigned ? "✓" : "✗")} Reloc{(info.HasReloc ? "✓" : "✗")}",
                $".NET{(info.IsDotNet ? "✓" : "✗")}",
                sizeStr);

            // 追加当前选中 stub 的兼容性警告（红字提示）
            // 选中"自动"时不附加 stub 相关警告（让 PackCore 自己选）
            string warning = null;
            var item = cbStubPreference?.SelectedItem as StubListItem;
            if (item != null && item.Manifest != null)
            {
                var (w, _) = GetStubCompatibilityWarning(item.Manifest.Kind, info);
                warning = w;
            }

            if (warning != null)
            {
                lblPeInfo.Text = $"{text}  |  {warning}";
                lblPeInfo.ForeColor = System.Drawing.Color.Red;
            }
            else
            {
                lblPeInfo.Text = text;
                // 警告色：.NET / Chromium 系浏览器 / 带签名（加壳后签名会失效）
                if (info.IsDotNet || info.IsChromiumLike || info.IsSigned)
                    lblPeInfo.ForeColor = System.Drawing.Color.OrangeRed;
                else
                    lblPeInfo.ForeColor = System.Drawing.Color.DarkSlateGray;
            }

            AppLogger.Info($"PE 信息: {text}{(warning != null ? "  警告: " + warning : "")}  路径: {exePath}");
        }

        private async void btnPack_Click(object sender, EventArgs e) {
            if (txtPassword.Text != txtConfirm.Text) {
                MessageBox.Show(this, "两次密码不一致", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            if (txtPassword.Text.Length < 4) {
                MessageBox.Show(this, "密码至少 4 个字符", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            // 覆盖已存在文件
            if (System.IO.File.Exists(txtOutputPath.Text)) {
                if (MessageBox.Show(this, $"输出文件已存在，是否覆盖？\n\n{txtOutputPath.Text}",
                        "确认", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                    return;
            }

            // 构造 PackOptions：根据 ComboBox 选中项
            var opts = new PackOptions {
                InputPath = txtInputPath.Text,
                OutputPath = txtOutputPath.Text,
                Password = txtPassword.Text,
                KdfIterations = (int)numIterations.Value
            };
            var selectedItem = cbStubPreference.SelectedItem as StubListItem;
            if (selectedItem != null && selectedItem.Manifest != null)
            {
                // 用户选了具体 stub
                opts.PreferStubName = selectedItem.Manifest.Name;
            }
            else
            {
                // 选了"自动"
                opts.StubPreference = StubPreference.Auto;
            }

            btnPack.Enabled = false;
            btnBrowseInput.Enabled = false;
            btnBrowseOutput.Enabled = false;
            progressBar.Value = 0;
            progressBar.Visible = true;
            lblResult.Text = "正在加密…";
            lblResult.ForeColor = System.Drawing.Color.Black;

            // 读取所选 exe 的 PE 信息后写入"开始加密"日志
            // 这样即便用户中途清空了 lblPeInfo 显示，日志里也有该 exe 的关键属性
            string peSummary = "(PE 读取失败)";
            try
            {
                byte[] pe = File.ReadAllBytes(opts.InputPath);
                var peInfo = PeReader.Parse(pe);
                peSummary = $"{peInfo.MachineName}/{peInfo.SubsystemName} " +
                            $"ASLR={peInfo.IsAslr} DEP={peInfo.IsDep} CFG={peInfo.IsCfg} HEVA={peInfo.IsHighEntropyVA} " +
                            $"TLS={peInfo.HasTls} Signed={peInfo.IsSigned} Reloc={peInfo.HasReloc} " +
                            $".NET={peInfo.IsDotNet} size={peInfo.FileSize}";
            }
            catch (Exception ex) { peSummary = $"(PE 读取失败: {ex.Message})"; }

            AppLogger.Info($"开始加密: input={opts.InputPath} output={opts.OutputPath} stub={(opts.PreferStubName ?? "auto")} iterations={opts.KdfIterations} PE=[{peSummary}]");

            var logs = new System.Collections.Concurrent.ConcurrentQueue<string>();
            try {
                var progress = new Progress<int>(p => {
                    progressBar.Value = Math.Min(100, p);
                    lblResult.Text = $"进度: {p}%";
                });

                var report = await System.Threading.Tasks.Task.Run(() =>
                    PackCore.Pack(opts, progress, msg => {
                        logs.Enqueue(msg);
                        // 按消息前缀区分级别写入 AppLogger
                        // PackCore / IconCopier / WinLock 的 "WARN:" / "ERROR:" / "[stderr]" 走 Warn，
                        // 其余走 Info
                        if (msg.Contains("WARN:") || msg.Contains("ERROR:") || msg.Contains("[stderr]"))
                            AppLogger.Warn(msg);
                        else
                            AppLogger.Info(msg);
                    }));

                // modeTag 显示加壳方案：[WinLock] / [Reflective] / 空（tempfile）
                string modeTag = report.UsedKind == StubKind.InplaceBuilder ? " [WinLock]"
                               : report.UsedKind == StubKind.ReflectiveBuilder ? " [Reflective]"
                               : "";
                lblResult.Text = $"✓ 加密成功{modeTag}：{report.InputSize / 1024.0:F1}KB → {report.OutputSize / 1024.0:F1}KB";
                lblResult.ForeColor = System.Drawing.Color.Green;

                AppLogger.Info($"加密成功: {report.InputSize} → {report.OutputSize} bytes, stub={report.UsedStubName} ({report.UsedKind})");
            } catch (Exception ex) {
                lblResult.Text = $"✗ 失败: {ex.Message}";
                lblResult.ForeColor = System.Drawing.Color.Red;
                AppLogger.Error($"加密失败: input={opts.InputPath} output={opts.OutputPath}", ex);
            } finally {
                btnPack.Enabled = true;
                btnBrowseInput.Enabled = true;
                btnBrowseOutput.Enabled = true;
                progressBar.Visible = false;
            }
        }
    }
}
