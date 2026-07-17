using System;
using System.Windows.Forms;

namespace WinAppLocker.Stub
{
    /// <summary>
    /// GUI stub 密码输入：弹 WinForms 对话框。取消返回 null。
    /// </summary>
    internal static class PasswordReader
    {
        public static string Ask(string title)
        {
            Application.EnableVisualStyles();
            using (var form = new PasswordForm(title))
            {
                return form.ShowDialog() == DialogResult.OK ? form.Password : null;
            }
        }
    }
}
