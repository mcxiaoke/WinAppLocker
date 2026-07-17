using System;
using System.Windows.Forms;

namespace WinAppLocker.Packer
{
    public partial class MainForm : Form
    {
        public MainForm()
        {
            InitializeComponent();
            // 在构造函数里加载图标（不放 Designer.cs，避免 VS 设计器报 "未找到方法 Form.LoadIcon"）
            try
            {
                var asm = System.Reflection.Assembly.GetExecutingAssembly();
                using (var stream = asm.GetManifestResourceStream("WinAppLocker.Packer.assets.app.ico"))
                {
                    if (stream != null)
                        this.Icon = new System.Drawing.Icon(stream);
                }
            }
            catch { }
        }

        private void MainForm_Load(object sender, EventArgs e)
        {
            lblPackerVersion.Text = $"Packer v{VersionInfo.Version}  git: {VersionInfo.GitHash}  build: {VersionInfo.BuildTime}";

            try
            {
                byte[] guiStub = StubLoader.SelectStub(2 /*WindowsGui*/, StubKind.Gui);
                string guiVer = StubLoader.ReadStubVersion(guiStub);
                lblStubGuiVersion.Text = guiVer != null ? $"Stub GUI    {guiVer}" : "Stub GUI    (版本未读取)";
            }
            catch (Exception ex)
            {
                lblStubGuiVersion.Text = $"Stub GUI    (未嵌入: {ex.Message})";
            }

            try
            {
                byte[] consoleStub = StubLoader.SelectStub(3 /*WindowsCui*/, StubKind.Console);
                string consoleVer = StubLoader.ReadStubVersion(consoleStub);
                lblStubConsoleVersion.Text = consoleVer != null ? $"Stub Console {consoleVer}" : "Stub Console (版本未读取)";
            }
            catch (Exception ex)
            {
                lblStubConsoleVersion.Text = $"Stub Console (未嵌入: {ex.Message})";
            }

            try
            {
                byte[] testStub = StubLoader.SelectStub(3 /*WindowsCui*/, StubKind.Test);
                string testVer = StubLoader.ReadStubVersion(testStub);
                lblStubTestVersion.Text = testVer != null ? $"Stub Test    {testVer}" : "Stub Test    (版本未读取)";
            }
            catch (Exception ex)
            {
                lblStubTestVersion.Text = $"Stub Test (未嵌入: {ex.Message})";
            }
        }

        private void btnBrowseInput_Click(object sender, EventArgs e)
        {
            using (var dlg = new OpenFileDialog())
            {
                dlg.Title = "选择原 EXE";
                dlg.Filter = "可执行文件 (*.exe)|*.exe|所有文件 (*.*)|*.*";
                dlg.CheckFileExists = true;
                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    txtInputPath.Text = dlg.FileName;
                    // 自动填充输出路径：原文件名_locked.exe 同目录
                    string dir = System.IO.Path.GetDirectoryName(dlg.FileName);
                    string name = System.IO.Path.GetFileNameWithoutExtension(dlg.FileName);
                    txtOutputPath.Text = System.IO.Path.Combine(dir, name + "_locked.exe");
                    UpdatePackButton();
                }
            }
        }

        private void btnBrowseOutput_Click(object sender, EventArgs e)
        {
            using (var dlg = new SaveFileDialog())
            {
                dlg.Title = "选择输出路径";
                dlg.Filter = "可执行文件 (*.exe)|*.exe";
                if (!string.IsNullOrEmpty(txtOutputPath.Text))
                {
                    dlg.FileName = System.IO.Path.GetFileName(txtOutputPath.Text);
                    dlg.InitialDirectory = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(txtOutputPath.Text));
                }
                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    txtOutputPath.Text = dlg.FileName;
                    UpdatePackButton();
                }
            }
        }

        private void btnTogglePassword_Click(object sender, EventArgs e)
        {
            bool showing = txtPassword.PasswordChar == '\0';
            txtPassword.PasswordChar = showing ? '*' : '\0';
            txtConfirm.PasswordChar = showing ? '*' : '\0';
            btnTogglePassword.Text = showing ? "隐藏" : "显示";
        }

        private void txt_TextChanged(object sender, EventArgs e)
        {
            UpdatePackButton();
        }

        private void UpdatePackButton()
        {
            bool ready = !string.IsNullOrEmpty(txtInputPath.Text)
                && !string.IsNullOrEmpty(txtOutputPath.Text)
                && !string.IsNullOrEmpty(txtPassword.Text)
                && txtPassword.Text == txtConfirm.Text;
            btnPack.Enabled = ready;
        }

        private async void btnPack_Click(object sender, EventArgs e)
        {
            if (txtPassword.Text != txtConfirm.Text)
            {
                MessageBox.Show(this, "两次密码不一致", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            if (txtPassword.Text.Length < 4)
            {
                MessageBox.Show(this, "密码至少 4 个字符", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            // 覆盖已存在文件
            if (System.IO.File.Exists(txtOutputPath.Text))
            {
                if (MessageBox.Show(this, $"输出文件已存在，是否覆盖？\n\n{txtOutputPath.Text}",
                        "确认", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                    return;
            }

            var opts = new PackOptions
            {
                InputPath = txtInputPath.Text,
                OutputPath = txtOutputPath.Text,
                Password = txtPassword.Text,
                StubPreference = (StubKind)cbStubPreference.SelectedIndex,
                KdfIterations = (int)numIterations.Value
            };

            btnPack.Enabled = false;
            btnBrowseInput.Enabled = false;
            btnBrowseOutput.Enabled = false;
            progressBar.Value = 0;
            progressBar.Visible = true;
            lblResult.Text = "正在加密…";
            lblResult.ForeColor = System.Drawing.Color.Black;

            var logs = new System.Collections.Concurrent.ConcurrentQueue<string>();
            try
            {
                var progress = new Progress<int>(p =>
                {
                    progressBar.Value = Math.Min(100, p);
                    lblResult.Text = $"进度: {p}%";
                });

                var report = await System.Threading.Tasks.Task.Run(() =>
                    PackCore.Pack(opts, progress, msg => logs.Enqueue(msg)));

                lblResult.Text = $"✓ 加密成功：{report.InputSize / 1024.0:F1}KB → {report.OutputSize / 1024.0:F1}KB";
                lblResult.ForeColor = System.Drawing.Color.Green;
            }
            catch (Exception ex)
            {
                lblResult.Text = $"✗ 失败: {ex.Message}";
                lblResult.ForeColor = System.Drawing.Color.Red;
            }
            finally
            {
                btnPack.Enabled = true;
                btnBrowseInput.Enabled = true;
                btnBrowseOutput.Enabled = true;
                progressBar.Visible = false;
            }
        }
    }
}
