using System;
using System.Windows.Forms;

namespace WinAppLocker.Stub
{
    /// <summary>GUI 密码对话框。</summary>
    internal partial class PasswordForm : Form
    {
        public string Password { get; private set; } = "";

        public PasswordForm(string title)
        {
            InitializeComponent();
            if (!string.IsNullOrEmpty(title))
            {
                Text = title;
            }
            // 加载嵌入的 app.ico（和 packer 同款加载方式）。
            // 不再尝试从原 exe 提取图标——WinForms 标题栏图标渲染对 ICO 流格式挑剔，
            // 从 PE 资源拼装的 ICO 流虽然能加载但渲染效果不佳（图标偏小、不居中）。
            // app.ico 是项目自带的标准多尺寸 ICO，加载后清晰。
            try
            {
                var asm = System.Reflection.Assembly.GetExecutingAssembly();
                using (var stream = asm.GetManifestResourceStream("WinAppLocker.Stub.app.ico"))
                {
                    if (stream != null)
                        this.Icon = new System.Drawing.Icon(stream);
                }
            }
            catch { }
        }

        private void btnOk_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(txtPassword.Text))
            {
                errorProvider.SetError(txtPassword, "密码不能为空");
                return;
            }
            Password = txtPassword.Text;
            DialogResult = DialogResult.OK;
            Close();
        }

        private void btnCancel_Click(object sender, EventArgs e)
        {
            DialogResult = DialogResult.Cancel;
            Close();
        }

        private void txtPassword_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter)
            {
                e.SuppressKeyPress = true;
                btnOk_Click(sender, e);
            }
            else if (e.KeyCode == Keys.Escape)
            {
                e.SuppressKeyPress = true;
                btnCancel_Click(sender, e);
            }
        }
    }
}
