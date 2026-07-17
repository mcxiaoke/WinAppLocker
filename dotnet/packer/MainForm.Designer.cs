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
            this.lblInputPath.Location = new System.Drawing.Point(15, 20);
            this.lblInputPath.Name = "lblInputPath";
            this.lblInputPath.Size = new System.Drawing.Size(64, 24);
            this.lblInputPath.TabIndex = 0;
            this.lblInputPath.Text = "输入：";
            // 
            // txtInputPath
            // 
            this.txtInputPath.Location = new System.Drawing.Point(95, 17);
            this.txtInputPath.Name = "txtInputPath";
            this.txtInputPath.Size = new System.Drawing.Size(420, 30);
            this.txtInputPath.TabIndex = 1;
            this.txtInputPath.TextChanged += new System.EventHandler(this.txt_TextChanged);
            // 
            // btnBrowseInput
            // 
            this.btnBrowseInput.Location = new System.Drawing.Point(525, 15);
            this.btnBrowseInput.Name = "btnBrowseInput";
            this.btnBrowseInput.Size = new System.Drawing.Size(75, 32);
            this.btnBrowseInput.TabIndex = 2;
            this.btnBrowseInput.Text = "浏览…";
            this.btnBrowseInput.Click += new System.EventHandler(this.btnBrowseInput_Click);
            // 
            // lblOutputPath
            // 
            this.lblOutputPath.AutoSize = true;
            this.lblOutputPath.Location = new System.Drawing.Point(15, 60);
            this.lblOutputPath.Name = "lblOutputPath";
            this.lblOutputPath.Size = new System.Drawing.Size(64, 24);
            this.lblOutputPath.TabIndex = 3;
            this.lblOutputPath.Text = "输出：";
            // 
            // txtOutputPath
            // 
            this.txtOutputPath.Location = new System.Drawing.Point(95, 57);
            this.txtOutputPath.Name = "txtOutputPath";
            this.txtOutputPath.Size = new System.Drawing.Size(420, 30);
            this.txtOutputPath.TabIndex = 4;
            this.txtOutputPath.TextChanged += new System.EventHandler(this.txt_TextChanged);
            // 
            // btnBrowseOutput
            // 
            this.btnBrowseOutput.Location = new System.Drawing.Point(525, 55);
            this.btnBrowseOutput.Name = "btnBrowseOutput";
            this.btnBrowseOutput.Size = new System.Drawing.Size(75, 32);
            this.btnBrowseOutput.TabIndex = 5;
            this.btnBrowseOutput.Text = "浏览…";
            this.btnBrowseOutput.Click += new System.EventHandler(this.btnBrowseOutput_Click);
            // 
            // lblPassword
            // 
            this.lblPassword.AutoSize = true;
            this.lblPassword.Location = new System.Drawing.Point(15, 100);
            this.lblPassword.Name = "lblPassword";
            this.lblPassword.Size = new System.Drawing.Size(64, 24);
            this.lblPassword.TabIndex = 6;
            this.lblPassword.Text = "密码：";
            // 
            // txtPassword
            // 
            this.txtPassword.Location = new System.Drawing.Point(95, 97);
            this.txtPassword.MaxLength = 256;
            this.txtPassword.Name = "txtPassword";
            this.txtPassword.PasswordChar = '*';
            this.txtPassword.Size = new System.Drawing.Size(420, 30);
            this.txtPassword.TabIndex = 7;
            this.txtPassword.TextChanged += new System.EventHandler(this.txt_TextChanged);
            // 
            // btnTogglePassword
            // 
            this.btnTogglePassword.Location = new System.Drawing.Point(525, 95);
            this.btnTogglePassword.Name = "btnTogglePassword";
            this.btnTogglePassword.Size = new System.Drawing.Size(75, 32);
            this.btnTogglePassword.TabIndex = 8;
            this.btnTogglePassword.Text = "显示";
            this.btnTogglePassword.Click += new System.EventHandler(this.btnTogglePassword_Click);
            // 
            // lblConfirm
            // 
            this.lblConfirm.AutoSize = true;
            this.lblConfirm.Location = new System.Drawing.Point(15, 140);
            this.lblConfirm.Name = "lblConfirm";
            this.lblConfirm.Size = new System.Drawing.Size(64, 24);
            this.lblConfirm.TabIndex = 9;
            this.lblConfirm.Text = "确认：";
            // 
            // txtConfirm
            // 
            this.txtConfirm.Location = new System.Drawing.Point(95, 137);
            this.txtConfirm.MaxLength = 256;
            this.txtConfirm.Name = "txtConfirm";
            this.txtConfirm.PasswordChar = '*';
            this.txtConfirm.Size = new System.Drawing.Size(420, 30);
            this.txtConfirm.TabIndex = 10;
            this.txtConfirm.TextChanged += new System.EventHandler(this.txt_TextChanged);
            // 
            // lblStubPref
            // 
            this.lblStubPref.AutoSize = true;
            this.lblStubPref.Location = new System.Drawing.Point(15, 180);
            this.lblStubPref.Name = "lblStubPref";
            this.lblStubPref.Size = new System.Drawing.Size(68, 24);
            this.lblStubPref.TabIndex = 11;
            this.lblStubPref.Text = "Stub：";
            // 
            // cbStubPreference
            // 
            this.cbStubPreference.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbStubPreference.Items.AddRange(new object[] {
            "自动",
            "GUI",
            "Console",
            "Test"});
            this.cbStubPreference.Location = new System.Drawing.Point(95, 177);
            this.cbStubPreference.Name = "cbStubPreference";
            this.cbStubPreference.Size = new System.Drawing.Size(150, 32);
            this.cbStubPreference.TabIndex = 12;
            // 
            // lblIterations
            // 
            this.lblIterations.AutoSize = true;
            this.lblIterations.Location = new System.Drawing.Point(260, 180);
            this.lblIterations.Name = "lblIterations";
            this.lblIterations.Size = new System.Drawing.Size(50, 24);
            this.lblIterations.TabIndex = 13;
            this.lblIterations.Text = "迭代:";
            // 
            // numIterations
            // 
            this.numIterations.Location = new System.Drawing.Point(305, 177);
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
            this.numIterations.Size = new System.Drawing.Size(120, 30);
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
            this.progressBar.Location = new System.Drawing.Point(15, 225);
            this.progressBar.Name = "progressBar";
            this.progressBar.Size = new System.Drawing.Size(585, 18);
            this.progressBar.TabIndex = 15;
            this.progressBar.Visible = false;
            // 
            // lblResult
            // 
            this.lblResult.AutoSize = true;
            this.lblResult.Location = new System.Drawing.Point(15, 250);
            this.lblResult.Name = "lblResult";
            this.lblResult.Size = new System.Drawing.Size(0, 24);
            this.lblResult.TabIndex = 16;
            // 
            // btnPack
            // 
            this.btnPack.Enabled = false;
            this.btnPack.Font = new System.Drawing.Font("Microsoft YaHei UI", 11F, System.Drawing.FontStyle.Bold);
            this.btnPack.Location = new System.Drawing.Point(19, 276);
            this.btnPack.Name = "btnPack";
            this.btnPack.Size = new System.Drawing.Size(581, 40);
            this.btnPack.TabIndex = 17;
            this.btnPack.Text = "执行加密操作";
            this.btnPack.Click += new System.EventHandler(this.btnPack_Click);
            // 
            // lblHint
            // 
            this.lblHint.AutoSize = true;
            this.lblHint.ForeColor = System.Drawing.Color.Gray;
            this.lblHint.Location = new System.Drawing.Point(15, 340);
            this.lblHint.Name = "lblHint";
            this.lblHint.Size = new System.Drawing.Size(322, 24);
            this.lblHint.TabIndex = 18;
            this.lblHint.Text = "提示：加密后的 EXE 需放在原目录运行";
            // 
            // lblPackerVersion
            // 
            this.lblPackerVersion.AutoSize = true;
            this.lblPackerVersion.ForeColor = System.Drawing.Color.DarkSlateGray;
            this.lblPackerVersion.Location = new System.Drawing.Point(15, 380);
            this.lblPackerVersion.Name = "lblPackerVersion";
            this.lblPackerVersion.Size = new System.Drawing.Size(67, 24);
            this.lblPackerVersion.TabIndex = 19;
            this.lblPackerVersion.Text = "Packer";
            // 
            // lblStubGuiVersion
            // 
            this.lblStubGuiVersion.AutoSize = true;
            this.lblStubGuiVersion.ForeColor = System.Drawing.Color.DarkSlateGray;
            this.lblStubGuiVersion.Location = new System.Drawing.Point(15, 400);
            this.lblStubGuiVersion.Name = "lblStubGuiVersion";
            this.lblStubGuiVersion.Size = new System.Drawing.Size(86, 24);
            this.lblStubGuiVersion.TabIndex = 20;
            this.lblStubGuiVersion.Text = "Stub GUI";
            // 
            // lblStubConsoleVersion
            // 
            this.lblStubConsoleVersion.AutoSize = true;
            this.lblStubConsoleVersion.ForeColor = System.Drawing.Color.DarkSlateGray;
            this.lblStubConsoleVersion.Location = new System.Drawing.Point(15, 420);
            this.lblStubConsoleVersion.Name = "lblStubConsoleVersion";
            this.lblStubConsoleVersion.Size = new System.Drawing.Size(123, 24);
            this.lblStubConsoleVersion.TabIndex = 21;
            this.lblStubConsoleVersion.Text = "Stub Console";
            // 
            // lblStubTestVersion
            // 
            this.lblStubTestVersion.AutoSize = true;
            this.lblStubTestVersion.ForeColor = System.Drawing.Color.DarkSlateGray;
            this.lblStubTestVersion.Location = new System.Drawing.Point(15, 440);
            this.lblStubTestVersion.Name = "lblStubTestVersion";
            this.lblStubTestVersion.Size = new System.Drawing.Size(90, 24);
            this.lblStubTestVersion.TabIndex = 22;
            this.lblStubTestVersion.Text = "Stub Test";
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(11F, 24F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(620, 490);
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
            this.Font = new System.Drawing.Font("Microsoft YaHei UI", 9F);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
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
