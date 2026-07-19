namespace WinAppLocker.Packer
{
    partial class MainForm
    {
        private System.ComponentModel.IContainer components = null;
        private System.Windows.Forms.Label lblInputPath;
        private System.Windows.Forms.TextBox txtInputPath;
        private System.Windows.Forms.Button btnBrowseInput;
        private System.Windows.Forms.Label lblOutputPath;
        private System.Windows.Forms.TextBox txtOutputPath;
        private System.Windows.Forms.Button btnBrowseOutput;
        private System.Windows.Forms.Label lblPassword;
        private System.Windows.Forms.TextBox txtPassword;
        private System.Windows.Forms.Button btnTogglePassword;
        private System.Windows.Forms.Label lblConfirm;
        private System.Windows.Forms.TextBox txtConfirm;
        private System.Windows.Forms.Label lblStubPref;
        private System.Windows.Forms.ComboBox cbStubPreference;
        private System.Windows.Forms.Label lblIterations;
        private System.Windows.Forms.NumericUpDown numIterations;
        private System.Windows.Forms.ProgressBar progressBar;
        private System.Windows.Forms.Label lblResult;
        private System.Windows.Forms.Button btnPack;
        private System.Windows.Forms.Label lblHint;
        private System.Windows.Forms.Label lblPackerVersion;
        private System.Windows.Forms.Label lblStubGuiVersion;
        private System.Windows.Forms.Label lblStubConsoleVersion;
        private System.Windows.Forms.Label lblStubTestVersion;

        protected override void Dispose(bool disposing)
        {
            if (disposing && components != null)
                components.Dispose();
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            this.lblInputPath = new System.Windows.Forms.Label();
            this.txtInputPath = new System.Windows.Forms.TextBox();
            this.btnBrowseInput = new System.Windows.Forms.Button();
            this.lblOutputPath = new System.Windows.Forms.Label();
            this.txtOutputPath = new System.Windows.Forms.TextBox();
            this.btnBrowseOutput = new System.Windows.Forms.Button();
            this.lblPassword = new System.Windows.Forms.Label();
            this.txtPassword = new System.Windows.Forms.TextBox();
            this.btnTogglePassword = new System.Windows.Forms.Button();
            this.lblConfirm = new System.Windows.Forms.Label();
            this.txtConfirm = new System.Windows.Forms.TextBox();
            this.lblStubPref = new System.Windows.Forms.Label();
            this.cbStubPreference = new System.Windows.Forms.ComboBox();
            this.lblIterations = new System.Windows.Forms.Label();
            this.numIterations = new System.Windows.Forms.NumericUpDown();
            this.progressBar = new System.Windows.Forms.ProgressBar();
            this.lblResult = new System.Windows.Forms.Label();
            this.btnPack = new System.Windows.Forms.Button();
            this.lblHint = new System.Windows.Forms.Label();
            this.lblPackerVersion = new System.Windows.Forms.Label();
            this.lblStubGuiVersion = new System.Windows.Forms.Label();
            this.lblStubConsoleVersion = new System.Windows.Forms.Label();
            this.lblStubTestVersion = new System.Windows.Forms.Label();
            ((System.ComponentModel.ISupportInitialize)(this.numIterations)).BeginInit();
            this.SuspendLayout();
            // 
            // lblInputPath
            // 
            this.lblInputPath.AutoSize = true;
            this.lblInputPath.Location = new System.Drawing.Point(18, 23);
            this.lblInputPath.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.lblInputPath.Name = "lblInputPath";
            this.lblInputPath.Size = new System.Drawing.Size(75, 28);
            this.lblInputPath.TabIndex = 0;
            this.lblInputPath.Text = "输入：";
            // 
            // txtInputPath
            // 
            this.txtInputPath.Location = new System.Drawing.Point(112, 20);
            this.txtInputPath.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.txtInputPath.Name = "txtInputPath";
            this.txtInputPath.Size = new System.Drawing.Size(496, 34);
            this.txtInputPath.TabIndex = 1;
            this.txtInputPath.TextChanged += new System.EventHandler(this.txt_TextChanged);
            // 
            // btnBrowseInput
            // 
            this.btnBrowseInput.Location = new System.Drawing.Point(620, 18);
            this.btnBrowseInput.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnBrowseInput.Name = "btnBrowseInput";
            this.btnBrowseInput.Size = new System.Drawing.Size(89, 37);
            this.btnBrowseInput.TabIndex = 2;
            this.btnBrowseInput.Text = "浏览…";
            this.btnBrowseInput.Click += new System.EventHandler(this.btnBrowseInput_Click);
            // 
            // lblOutputPath
            // 
            this.lblOutputPath.AutoSize = true;
            this.lblOutputPath.Location = new System.Drawing.Point(18, 70);
            this.lblOutputPath.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.lblOutputPath.Name = "lblOutputPath";
            this.lblOutputPath.Size = new System.Drawing.Size(75, 28);
            this.lblOutputPath.TabIndex = 3;
            this.lblOutputPath.Text = "输出：";
            // 
            // txtOutputPath
            // 
            this.txtOutputPath.Location = new System.Drawing.Point(112, 66);
            this.txtOutputPath.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.txtOutputPath.Name = "txtOutputPath";
            this.txtOutputPath.Size = new System.Drawing.Size(496, 34);
            this.txtOutputPath.TabIndex = 4;
            this.txtOutputPath.TextChanged += new System.EventHandler(this.txt_TextChanged);
            // 
            // btnBrowseOutput
            // 
            this.btnBrowseOutput.Location = new System.Drawing.Point(620, 64);
            this.btnBrowseOutput.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnBrowseOutput.Name = "btnBrowseOutput";
            this.btnBrowseOutput.Size = new System.Drawing.Size(89, 37);
            this.btnBrowseOutput.TabIndex = 5;
            this.btnBrowseOutput.Text = "浏览…";
            this.btnBrowseOutput.Click += new System.EventHandler(this.btnBrowseOutput_Click);
            // 
            // lblPassword
            // 
            this.lblPassword.AutoSize = true;
            this.lblPassword.Location = new System.Drawing.Point(18, 117);
            this.lblPassword.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.lblPassword.Name = "lblPassword";
            this.lblPassword.Size = new System.Drawing.Size(75, 28);
            this.lblPassword.TabIndex = 6;
            this.lblPassword.Text = "密码：";
            // 
            // txtPassword
            // 
            this.txtPassword.Location = new System.Drawing.Point(112, 113);
            this.txtPassword.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.txtPassword.MaxLength = 256;
            this.txtPassword.Name = "txtPassword";
            this.txtPassword.PasswordChar = '*';
            this.txtPassword.Size = new System.Drawing.Size(496, 34);
            this.txtPassword.TabIndex = 7;
            this.txtPassword.TextChanged += new System.EventHandler(this.txt_TextChanged);
            //
            // btnTogglePassword
            //
            this.btnTogglePassword.Location = new System.Drawing.Point(620, 111);
            this.btnTogglePassword.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnTogglePassword.Name = "btnTogglePassword";
            this.btnTogglePassword.Size = new System.Drawing.Size(89, 37);
            this.btnTogglePassword.TabIndex = 8;
            this.btnTogglePassword.TabStop = false;
            this.btnTogglePassword.Text = "显示";
            this.btnTogglePassword.Click += new System.EventHandler(this.btnTogglePassword_Click);
            // 
            // lblConfirm
            // 
            this.lblConfirm.AutoSize = true;
            this.lblConfirm.Location = new System.Drawing.Point(18, 163);
            this.lblConfirm.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.lblConfirm.Name = "lblConfirm";
            this.lblConfirm.Size = new System.Drawing.Size(75, 28);
            this.lblConfirm.TabIndex = 9;
            this.lblConfirm.Text = "确认：";
            // 
            // txtConfirm
            // 
            this.txtConfirm.Location = new System.Drawing.Point(112, 160);
            this.txtConfirm.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.txtConfirm.MaxLength = 256;
            this.txtConfirm.Name = "txtConfirm";
            this.txtConfirm.PasswordChar = '*';
            this.txtConfirm.Size = new System.Drawing.Size(496, 34);
            this.txtConfirm.TabIndex = 10;
            this.txtConfirm.TextChanged += new System.EventHandler(this.txt_TextChanged);
            // 
            // lblStubPref
            // 
            this.lblStubPref.AutoSize = true;
            this.lblStubPref.Location = new System.Drawing.Point(18, 210);
            this.lblStubPref.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.lblStubPref.Name = "lblStubPref";
            this.lblStubPref.Size = new System.Drawing.Size(79, 28);
            this.lblStubPref.TabIndex = 11;
            this.lblStubPref.Text = "Stub：";
            // 
            // cbStubPreference
            // 
            this.cbStubPreference.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            // 注意：Items 不在 Designer 里硬编码，由 MainForm.LoadStubList() 在 Load 时动态填充
            this.cbStubPreference.Location = new System.Drawing.Point(112, 206);
            this.cbStubPreference.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.cbStubPreference.Name = "cbStubPreference";
            this.cbStubPreference.Size = new System.Drawing.Size(397, 36);
            this.cbStubPreference.TabIndex = 12;
            this.cbStubPreference.SelectedIndexChanged += new System.EventHandler(this.cbStubPreference_SelectedIndexChanged);
            // 
            // lblIterations
            // 
            this.lblIterations.AutoSize = true;
            this.lblIterations.Location = new System.Drawing.Point(307, 210);
            this.lblIterations.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.lblIterations.Name = "lblIterations";
            this.lblIterations.Size = new System.Drawing.Size(75, 28);
            this.lblIterations.TabIndex = 13;
            this.lblIterations.Text = "迭代：";
            // 
            // numIterations
            // 
            this.numIterations.Location = new System.Drawing.Point(393, 206);
            this.numIterations.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.numIterations.Maximum = new decimal(new int[] {
            5000000,
            0,
            0,
            0});
            this.numIterations.Minimum = new decimal(new int[] {
            10000,
            0,
            0,
            0});
            this.numIterations.Name = "numIterations";
            this.numIterations.Size = new System.Drawing.Size(142, 34);
            this.numIterations.TabIndex = 14;
            this.numIterations.ThousandsSeparator = true;
            this.numIterations.Value = new decimal(new int[] {
            200000,
            0,
            0,
            0});
            // 
            // progressBar
            // 
            this.progressBar.Location = new System.Drawing.Point(18, 262);
            this.progressBar.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.progressBar.Name = "progressBar";
            this.progressBar.Size = new System.Drawing.Size(691, 21);
            this.progressBar.TabIndex = 15;
            this.progressBar.Visible = false;
            // 
            // lblResult
            // 
            this.lblResult.AutoSize = true;
            this.lblResult.Location = new System.Drawing.Point(18, 292);
            this.lblResult.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.lblResult.Name = "lblResult";
            this.lblResult.Size = new System.Drawing.Size(0, 28);
            this.lblResult.TabIndex = 16;
            // 
            // btnPack
            // 
            this.btnPack.Enabled = false;
            this.btnPack.Font = new System.Drawing.Font("Microsoft YaHei UI", 11F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(134)));
            this.btnPack.Location = new System.Drawing.Point(22, 322);
            this.btnPack.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnPack.Name = "btnPack";
            this.btnPack.Size = new System.Drawing.Size(687, 47);
            this.btnPack.TabIndex = 17;
            this.btnPack.Text = "执行加密操作";
            this.btnPack.Click += new System.EventHandler(this.btnPack_Click);
            // 
            // lblHint
            // 
            this.lblHint.AutoSize = true;
            this.lblHint.ForeColor = System.Drawing.Color.Gray;
            this.lblHint.Location = new System.Drawing.Point(18, 397);
            this.lblHint.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.lblHint.Name = "lblHint";
            this.lblHint.Size = new System.Drawing.Size(377, 28);
            this.lblHint.TabIndex = 18;
            this.lblHint.Text = "提示：加密后的 EXE 需放在原目录运行";
            // 
            // lblPackerVersion
            // 
            this.lblPackerVersion.AutoSize = true;
            this.lblPackerVersion.Font = new System.Drawing.Font("Microsoft YaHei UI", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(134)));
            this.lblPackerVersion.ForeColor = System.Drawing.Color.DarkSlateGray;
            this.lblPackerVersion.Location = new System.Drawing.Point(18, 443);
            this.lblPackerVersion.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.lblPackerVersion.Name = "lblPackerVersion";
            this.lblPackerVersion.Size = new System.Drawing.Size(67, 24);
            this.lblPackerVersion.TabIndex = 19;
            this.lblPackerVersion.Text = "Packer";
            // 
            // lblStubGuiVersion
            // 
            this.lblStubGuiVersion.AutoSize = true;
            this.lblStubGuiVersion.Font = new System.Drawing.Font("Microsoft YaHei UI", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(134)));
            this.lblStubGuiVersion.ForeColor = System.Drawing.Color.DarkSlateGray;
            this.lblStubGuiVersion.Location = new System.Drawing.Point(18, 467);
            this.lblStubGuiVersion.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.lblStubGuiVersion.Name = "lblStubGuiVersion";
            this.lblStubGuiVersion.Size = new System.Drawing.Size(86, 24);
            this.lblStubGuiVersion.TabIndex = 20;
            this.lblStubGuiVersion.Text = "Stub GUI";
            // 
            // lblStubConsoleVersion
            // 
            this.lblStubConsoleVersion.AutoSize = true;
            this.lblStubConsoleVersion.Font = new System.Drawing.Font("Microsoft YaHei UI", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(134)));
            this.lblStubConsoleVersion.ForeColor = System.Drawing.Color.DarkSlateGray;
            this.lblStubConsoleVersion.Location = new System.Drawing.Point(18, 490);
            this.lblStubConsoleVersion.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.lblStubConsoleVersion.Name = "lblStubConsoleVersion";
            this.lblStubConsoleVersion.Size = new System.Drawing.Size(123, 24);
            this.lblStubConsoleVersion.TabIndex = 21;
            this.lblStubConsoleVersion.Text = "Stub Console";
            // 
            // lblStubTestVersion
            // 
            this.lblStubTestVersion.AutoSize = true;
            this.lblStubTestVersion.Font = new System.Drawing.Font("Microsoft YaHei UI", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(134)));
            this.lblStubTestVersion.ForeColor = System.Drawing.Color.DarkSlateGray;
            this.lblStubTestVersion.Location = new System.Drawing.Point(18, 513);
            this.lblStubTestVersion.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.lblStubTestVersion.Name = "lblStubTestVersion";
            this.lblStubTestVersion.Size = new System.Drawing.Size(90, 24);
            this.lblStubTestVersion.TabIndex = 22;
            this.lblStubTestVersion.Text = "Stub Test";
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(13F, 28F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(737, 551);
            this.Controls.Add(this.lblInputPath);
            this.Controls.Add(this.txtInputPath);
            this.Controls.Add(this.btnBrowseInput);
            this.Controls.Add(this.lblOutputPath);
            this.Controls.Add(this.txtOutputPath);
            this.Controls.Add(this.btnBrowseOutput);
            this.Controls.Add(this.lblPassword);
            this.Controls.Add(this.txtPassword);
            this.Controls.Add(this.btnTogglePassword);
            this.Controls.Add(this.lblConfirm);
            this.Controls.Add(this.txtConfirm);
            this.Controls.Add(this.lblStubPref);
            this.Controls.Add(this.cbStubPreference);
            this.Controls.Add(this.lblIterations);
            this.Controls.Add(this.numIterations);
            this.Controls.Add(this.progressBar);
            this.Controls.Add(this.lblResult);
            this.Controls.Add(this.btnPack);
            this.Controls.Add(this.lblHint);
            this.Controls.Add(this.lblPackerVersion);
            this.Controls.Add(this.lblStubGuiVersion);
            this.Controls.Add(this.lblStubConsoleVersion);
            this.Controls.Add(this.lblStubTestVersion);
            this.Font = new System.Drawing.Font("Microsoft YaHei UI", 10.5F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(134)));
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "MainForm";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "WinAppLocker - EXE 密码保护工具";
            this.Load += new System.EventHandler(this.MainForm_Load);
            ((System.ComponentModel.ISupportInitialize)(this.numIterations)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }
    }
}
