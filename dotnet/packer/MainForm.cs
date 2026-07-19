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
        }

        private void MainForm_Load(object sender, EventArgs e) {
            lblPackerVersion.Text = $"Packer v{VersionInfo.Version}  git: {VersionInfo.GitHash}  build: {VersionInfo.BuildTime}";

            // 动态加载 stub 列表
            LoadStubList();

            // 显示每个已加载 stub 的版本信息（替代旧的硬编码 3 个 label）
            UpdateStubVersionLabels();
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
                else if (s.Kind == StubKind.InplaceBuilder)
                    label += " (兼容性较低)";
                cbStubPreference.Items.Add(new StubListItem(s, label));
            }
            cbStubPreference.SelectedIndex = 0;
        }

        /// <summary>更新版本信息 label：显示所有可用 stub 的版本</summary>
        private void UpdateStubVersionLabels()
        {
            // 旧的 3 个 label 改为只显示汇总信息（避免界面太长）
            var available = _availableStubs.Where(s => s.IsAvailable).ToList();
            var missing = _availableStubs.Where(s => !s.IsAvailable).ToList();

            if (_availableStubs.Count == 0)
            {
                lblStubGuiVersion.Text = "[无可用 stub]";
                lblStubGuiVersion.ForeColor = System.Drawing.Color.Red;
                lblStubConsoleVersion.Text = "  请检查 stub/ 目录是否存在";
                lblStubConsoleVersion.ForeColor = System.Drawing.Color.Red;
                lblStubTestVersion.Text = $"  期望路径: {StubLoader.FindStubDir()}";
                lblStubTestVersion.ForeColor = System.Drawing.Color.Gray;
                return;
            }

            // 列出可用的 stub 名称
            lblStubGuiVersion.Text = $"可用 stub（{available.Count}）: " +
                string.Join(", ", available.Select(s => s.Name));
            lblStubGuiVersion.ForeColor = System.Drawing.Color.DarkSlateGray;

            if (missing.Count > 0)
            {
                lblStubConsoleVersion.Text = $"缺失 stub（{missing.Count}）: " +
                    string.Join(", ", missing.Select(s => $"{s.Name}({string.Join(",", s.MissingComponents)})"));
                lblStubConsoleVersion.ForeColor = System.Drawing.Color.OrangeRed;
            }
            else
            {
                lblStubConsoleVersion.Text = "  所有 stub 文件完整";
                lblStubConsoleVersion.ForeColor = System.Drawing.Color.DarkSlateGray;
            }

            // 显示 tempfile stub 的版本号（取第一个 tempfile 类型的）
            var tempfileStub = available.FirstOrDefault(s => s.Kind == StubKind.Tempfile);
            if (tempfileStub != null)
            {
                try
                {
                    byte[] stubBytes = File.ReadAllBytes(tempfileStub.MainFilePath);
                    string ver = StubLoader.ReadStubVersion(stubBytes);
                    lblStubTestVersion.Text = ver != null ? $"  {tempfileStub.Name} 版本: {ver}" : $"  {tempfileStub.Name} (版本未读取)";
                }
                catch
                {
                    lblStubTestVersion.Text = $"  {tempfileStub.Name} (读取版本失败)";
                }
                lblStubTestVersion.ForeColor = System.Drawing.Color.DarkSlateGray;
            }
            else
            {
                lblStubTestVersion.Text = "  (无 tempfile stub)";
                lblStubTestVersion.ForeColor = System.Drawing.Color.Gray;
            }
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
                    UpdatePackButton();
                    // 选了输入文件后，检查 WinLock + Console 子系统组合，警告
                    WarnIfIncompatible();
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

        /// <summary>当用户选了 WinLock 但原 EXE 是 Console 子系统时弹警告</summary>
        private void WarnIfIncompatible()
        {
            if (string.IsNullOrEmpty(txtInputPath.Text) || !File.Exists(txtInputPath.Text))
                return;
            if (!(cbStubPreference.SelectedItem is StubListItem item) || item.Manifest == null)
                return;
            if (item.Manifest.Kind != StubKind.InplaceBuilder)
                return;

            try
            {
                byte[] pe = File.ReadAllBytes(txtInputPath.Text);
                var peInfo = PeReader.Parse(pe);
                if (peInfo.IsDotNet)
                {
                    MessageBox.Show(this,
                        "WinLock 模式不支持 .NET CLR 托管 PE。\n请改用临时文件模式（applocker-gui / applocker-console）。",
                        "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                if (peInfo.Subsystem != 2 /* WindowsGui */)
                {
                    MessageBox.Show(this,
                        "WinLock 模式仅支持 GUI 程序。\n建议改用 AppLocker Console 模式。",
                        "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
            catch { /* 解析失败不弹框，让 PackCore 报错 */ }
        }

        /// <summary>ComboBox 选中项变化时检查兼容性</summary>
        private void cbStubPreference_SelectedIndexChanged(object sender, EventArgs e)
        {
            WarnIfIncompatible();
        }

        private void UpdatePackButton() {
            bool ready = !string.IsNullOrEmpty(txtInputPath.Text)
                && !string.IsNullOrEmpty(txtOutputPath.Text)
                && !string.IsNullOrEmpty(txtPassword.Text)
                && txtPassword.Text == txtConfirm.Text;
            btnPack.Enabled = ready;
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

            var logs = new System.Collections.Concurrent.ConcurrentQueue<string>();
            try {
                var progress = new Progress<int>(p => {
                    progressBar.Value = Math.Min(100, p);
                    lblResult.Text = $"进度: {p}%";
                });

                var report = await System.Threading.Tasks.Task.Run(() =>
                    PackCore.Pack(opts, progress, msg => logs.Enqueue(msg)));

                string modeTag = report.UsedKind == StubKind.InplaceBuilder ? " [WinLock]" : "";
                lblResult.Text = $"✓ 加密成功{modeTag}：{report.InputSize / 1024.0:F1}KB → {report.OutputSize / 1024.0:F1}KB";
                lblResult.ForeColor = System.Drawing.Color.Green;
            } catch (Exception ex) {
                lblResult.Text = $"✗ 失败: {ex.Message}";
                lblResult.ForeColor = System.Drawing.Color.Red;
            } finally {
                btnPack.Enabled = true;
                btnBrowseInput.Enabled = true;
                btnBrowseOutput.Enabled = true;
                progressBar.Visible = false;
            }
        }
    }
}
