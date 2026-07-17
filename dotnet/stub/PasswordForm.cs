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
