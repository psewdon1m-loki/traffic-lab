using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

internal static class PortableGui
{
    public static int Run(bool autoStartExtended = false)
    {
        HideConsoleWindow();
        ApplicationConfiguration.Initialize();
        using var form = new TrafficLabForm(autoStartExtended);
        Application.Run(form);
        return form.ExitCode;
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr window, int command);
    private static void HideConsoleWindow()
    {
        var window = GetConsoleWindow();
        if (window != IntPtr.Zero) ShowWindow(window, 0);
    }
}

internal sealed class TrafficLabForm : Form
{
    private readonly string baseDirectory = AppContext.BaseDirectory;
    private readonly string connectionFile;
    private readonly Label inputLabel = new();
    private readonly Label statusLabel = new();
    private readonly Label timeLabel = new();
    private readonly ProgressBar progress = new();
    private readonly Button startButton = new();
    private readonly Button extendedButton = new();
    private readonly Button stopButton = new();
    private readonly Button saveButton = new();
    private readonly Button openFolderButton = new();
    private readonly TextBox details = new();
    private readonly System.Windows.Forms.Timer timer = new() { Interval = 1000 };
    private readonly Stopwatch elapsed = new();
    private bool isRunning;
    private bool isExporting;
    private CancellationTokenSource? runCancellation;
    private string? resultZip;
    private int profileCount;
    private double expectedSeconds;
    private int observedProgress;
    private bool currentRunExtended;
    private readonly StringBuilder output = new();
    public int ExitCode { get; private set; }

    public TrafficLabForm(bool autoStartExtended = false)
    {
        connectionFile = Path.Combine(baseDirectory, "connections.txt");
        Text = "Loki Traffic Lab Portable 3.2.0";
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(820, 430);
        Size = new Size(900, 500);
        Font = new Font("Segoe UI", 10f);
        AutoScaleMode = AutoScaleMode.Dpi;

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(28),
            ColumnCount = 1,
            RowCount = 7
        };
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 58));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 54));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 35));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 46));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        var title = new Label
        {
            Text = "Loki Traffic Lab",
            Font = new Font("Segoe UI Semibold", 20f),
            TextAlign = ContentAlignment.MiddleCenter,
            Dock = DockStyle.Fill
        };
        inputLabel.TextAlign = ContentAlignment.MiddleCenter;
        inputLabel.Dock = DockStyle.Fill;

        startButton.Text = "START TEST";
        startButton.Font = new Font("Segoe UI Semibold", 13f);
        startButton.Size = new Size(190, 54);
        startButton.Click += StartClicked;
        extendedButton.Text = "EXTENDED TEST";
        extendedButton.Font = new Font("Segoe UI Semibold", 13f);
        extendedButton.Size = new Size(230, 54);
        extendedButton.Click += ExtendedClicked;
        stopButton.Text = "STOP TEST";
        stopButton.Font = new Font("Segoe UI Semibold", 13f);
        stopButton.Size = new Size(190, 54);
        stopButton.Enabled = false;
        stopButton.Click += StopClicked;
        var testButtons = new FlowLayoutPanel
        {
            AutoSize = true,
            Anchor = AnchorStyles.None,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false
        };
        testButtons.Controls.Add(startButton);
        testButtons.Controls.Add(extendedButton);
        testButtons.Controls.Add(stopButton);

        progress.Dock = DockStyle.Fill;
        progress.Style = ProgressBarStyle.Continuous;
        progress.Minimum = 0;
        progress.Maximum = 100;
        statusLabel.Text = "Готово к запуску";
        statusLabel.TextAlign = ContentAlignment.MiddleCenter;
        statusLabel.Dock = DockStyle.Fill;
        timeLabel.TextAlign = ContentAlignment.MiddleCenter;
        timeLabel.Dock = DockStyle.Fill;

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
        buttons.Controls.Add(saveButton);
        buttons.Controls.Add(openFolderButton);
        saveButton.Text = "Сохранить ZIP в Загрузки";
        saveButton.AutoSize = true;
        saveButton.Enabled = false;
        saveButton.Click += SaveClicked;
        openFolderButton.Text = "Открыть папку результатов";
        openFolderButton.AutoSize = true;
        openFolderButton.Enabled = false;
        openFolderButton.Click += OpenFolderClicked;

        details.Dock = DockStyle.Fill;
        details.Multiline = true;
        details.ReadOnly = true;
        details.ScrollBars = ScrollBars.Vertical;
        details.BackColor = SystemColors.Window;

        layout.Controls.Add(title, 0, 0);
        layout.Controls.Add(inputLabel, 0, 1);
        layout.Controls.Add(testButtons, 0, 2);
        layout.Controls.Add(progress, 0, 3);
        layout.Controls.Add(statusLabel, 0, 4);
        layout.Controls.Add(timeLabel, 0, 5);
        layout.Controls.Add(details, 0, 6);
        Controls.Add(layout);
        Controls.Add(buttons);
        buttons.Dock = DockStyle.Bottom;
        buttons.Height = 42;
        buttons.Padding = new Padding(25, 4, 0, 0);

        timer.Tick += (_, _) => UpdateProgress();
        FormClosing += OnClosing;
        RefreshInputState();
        if (autoStartExtended)
            Shown += async (_, _) => await StartTestAsync(extended: true);
    }

    private void RefreshInputState()
    {
        try
        {
            var input = ConnectionFileLoader.Load(connectionFile);
            profileCount = input.Entries.Count;
            inputLabel.Text = $"connections.txt: {profileCount} подключений, тестирование последовательно";
            startButton.Enabled = true;
            extendedButton.Enabled = true;
        }
        catch
        {
            profileCount = 0;
            inputLabel.Text = "Добавьте подключения в connections.txt — по одному VLESS URI на строку";
            startButton.Enabled = false;
            extendedButton.Enabled = false;
        }
    }

    private async void StartClicked(object? sender, EventArgs e)
        => await StartTestAsync(extended: false);

    private async void ExtendedClicked(object? sender, EventArgs e)
    {
        var consent = MessageBox.Show(this,
            "EXTENDED TEST займёт не менее 5 минут на каждое подключение, создаст параллельные TCP/UDP-потоки, принудительно перезапустит только лабораторный Xray и примерно на 5 секунд заблокирует только его через Windows Firewall.\r\n\r\nСетевой адаптер и другие приложения отключаться не будут. Временное правило удаляется даже при STOP TEST. Продолжить?",
            "Расширенный тест", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
        if (consent != DialogResult.Yes) return;

        if (!Program.IsCurrentProcessElevated())
        {
            try
            {
                var executable = Environment.ProcessPath ?? Application.ExecutablePath;
                var elevated = Process.Start(new ProcessStartInfo
                {
                    FileName = executable,
                    Arguments = "--extended-gui",
                    WorkingDirectory = baseDirectory,
                    UseShellExecute = true,
                    Verb = "runas",
                    WindowStyle = ProcessWindowStyle.Normal
                });
                if (elevated is not null) Close();
            }
            catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                statusLabel.Text = "Расширенный тест отменён: повышение прав не подтверждено";
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Не удалось запустить расширенный тест с правами администратора:\r\n" + ProgramAccess.Redact(ex.Message),
                    "Traffic Lab", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            return;
        }

        await StartTestAsync(extended: true);
    }

    private async Task StartTestAsync(bool extended)
    {
        RefreshInputState();
        if (profileCount == 0) return;
        var conflicts = ProxyConflictDetector.Scan();
        if (conflicts.Count > 0)
        {
            MessageBox.Show(this,
                "Обнаружено другое активное прокси/VPN-соединение:\r\n\r\n" + string.Join("\r\n", conflicts.Select(item => "• " + item)) +
                "\r\n\r\nОтключите его и снова нажмите START TEST. Иначе direct baseline и выводы о маршруте будут недостоверными.",
                "Нужно отключить другое прокси", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            statusLabel.Text = "Тест не запущен: обнаружено другое прокси/VPN";
            return;
        }

        runCancellation?.Dispose();
        runCancellation = new CancellationTokenSource();
        isRunning = true;
        currentRunExtended = extended;
        startButton.Enabled = false;
        extendedButton.Enabled = false;
        stopButton.Enabled = true;
        saveButton.Enabled = false;
        openFolderButton.Enabled = false;
        resultZip = null;
        output.Clear();
        details.Clear();
        progress.Value = 1;
        observedProgress = 1;
        expectedSeconds = 25 + (extended ? 430 : 55) * profileCount;
        elapsed.Restart();
        timer.Start();
        statusLabel.Text = extended ? "Расширенный тест: сбор характеристик локальной машины…" : "Сбор характеристик локальной машины…";

        var artifacts = Path.Combine(baseDirectory, "artifacts");
        Directory.CreateDirectory(artifacts);
        var arguments = new List<string>
        {
            "run", "--connections", connectionFile, "--outdir", artifacts,
            "--history", Path.Combine(artifacts, "history.sqlite"),
            "--dns-attempts", "3", "--tcp-attempts", "5", "--stability-attempts", "10",
            "--negative-controls", "--xudp"
        };
        arguments.AddRange(["--test-type", extended ? "extended" : "normal"]);
        if (extended)
        {
            arguments.AddRange(["--soak-seconds", "300", "--parallel-flows", "20", "--network-loss-seconds", "5"]);
        }

        try
        {
            var cancellationToken = runCancellation.Token;
            ExitCode = await Task.Run(() => Program.RunCliAsync(arguments.ToArray(), line => HandleOutput(line, false), cancellationToken), cancellationToken);
        }
        catch (OperationCanceledException)
        {
            ExitCode = 130;
        }
        catch (Exception ex)
        {
            ExitCode = 2;
            AppendDetails("Ошибка запуска: " + ProgramAccess.Redact(ex.Message));
        }
        finally
        {
            timer.Stop();
            elapsed.Stop();
            isRunning = false;
            stopButton.Enabled = false;
            runCancellation?.Dispose();
            runCancellation = null;
        }

        if (ExitCode != 130 && (string.IsNullOrWhiteSpace(resultZip) || !File.Exists(resultZip)))
        {
            resultZip = Directory.EnumerateFiles(artifacts, "traffic-lab-results-*.zip")
                .Select(path => new FileInfo(path)).OrderByDescending(item => item.LastWriteTimeUtc).FirstOrDefault()?.FullName;
        }
        if (ExitCode == 130)
        {
            resultZip = null;
            progress.Value = 0;
            observedProgress = 0;
            statusLabel.Text = "Тест принудительно остановлен. Частичный архив не создан.";
            timeLabel.Text = $"Остановлено через: {FormatTime(elapsed.Elapsed)} · следующий START начнёт тест сначала";
            AppendDetails("STOP TEST: текущий прогон отменён, временный Xray завершён, незавершённые результаты удалены.");
        }
        else if (ExitCode == 0 && resultZip is not null && File.Exists(resultZip))
        {
            progress.Value = 100;
            var sizeMb = new FileInfo(resultZip).Length / 1024d / 1024d;
            statusLabel.Text = $"{(currentRunExtended ? "Расширенный" : "Обычный")} тест завершён. Итоговый архив: {sizeMb:F2} МБ";
            timeLabel.Text = $"Прошло: {FormatTime(elapsed.Elapsed)} · осталось: 00:00";
            saveButton.Enabled = true;
            openFolderButton.Enabled = true;
            MessageBox.Show(this, "Тестирование завершено. Нажмите «Сохранить ZIP в Загрузки».", "Traffic Lab", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        else
        {
            progress.Value = Math.Min(99, progress.Value);
            statusLabel.Text = $"Тест завершился с ошибкой (код {ExitCode}). Подробности показаны ниже.";
        }
        startButton.Enabled = true;
        extendedButton.Enabled = true;
    }

    private void StopClicked(object? sender, EventArgs e)
    {
        if (!isRunning || runCancellation is null || runCancellation.IsCancellationRequested) return;
        stopButton.Enabled = false;
        statusLabel.Text = "Принудительная остановка теста и завершение Xray…";
        AppendDetails("STOP TEST: запрошена полная остановка текущего прогона.");
        runCancellation.Cancel();
    }

    private void HandleOutput(string line, bool error)
    {
        lock (output) output.AppendLine((error ? "ERROR: " : "") + line);
        if (line.StartsWith("ZIP :", StringComparison.OrdinalIgnoreCase)) resultZip = line[5..].Trim();
        var match = Regex.Match(line, @"Testing profile-(?<number>\d+):", RegexOptions.IgnoreCase);
        if (match.Success && int.TryParse(match.Groups["number"].Value, out var current))
        {
            observedProgress = Math.Max(observedProgress, 15 + (int)Math.Floor((current - 1) * 78d / Math.Max(1, profileCount)));
            SetStatus($"Тестирование подключения {current} из {profileCount}…");
        }
        else if (Regex.Match(line, @"profile-(?<number>\d+): extended soak: (?<percent>\d+)%", RegexOptions.IgnoreCase) is { Success: true } soakMatch
            && int.TryParse(soakMatch.Groups["number"].Value, out var soakProfile)
            && int.TryParse(soakMatch.Groups["percent"].Value, out var soakPercent))
        {
            var profileStart = 15 + (soakProfile - 1) * 78d / Math.Max(1, profileCount);
            var localPercent = 95 + Math.Clamp(soakPercent, 0, 100) * 0.02;
            observedProgress = Math.Max(observedProgress, (int)Math.Floor(profileStart + 78d / Math.Max(1, profileCount) * localPercent / 100d));
            SetStatus($"Расширенный тест: soak подключения {soakProfile} из {profileCount} — {soakPercent}%");
        }
        else if (line.Contains(": extended:", StringComparison.OrdinalIgnoreCase)) SetStatus("Расширенный тест: " + line[(line.IndexOf(": extended:", StringComparison.OrdinalIgnoreCase) + 12)..]);
        else if (line.Contains("Capturing direct-network baseline", StringComparison.OrdinalIgnoreCase)) SetStatus("Проверка локальной сети и direct baseline…");
        else if (line.Contains("profile summary", StringComparison.OrdinalIgnoreCase)) observedProgress = Math.Max(observedProgress, 94);
        AppendDetails(line);
    }

    private void SetStatus(string value)
    {
        if (InvokeRequired) BeginInvoke(() => statusLabel.Text = value); else statusLabel.Text = value;
    }

    private void AppendDetails(string line)
    {
        if (InvokeRequired) { BeginInvoke(() => AppendDetails(line)); return; }
        details.AppendText(line + Environment.NewLine);
        if (details.TextLength > 24_000) details.Text = details.Text[^18_000..];
        details.SelectionStart = details.TextLength;
        details.ScrollToCaret();
    }

    private void UpdateProgress()
    {
        if (!elapsed.IsRunning) return;
        if (elapsed.Elapsed.TotalSeconds > expectedSeconds) expectedSeconds += 30;
        var timeBased = (int)Math.Min(94, elapsed.Elapsed.TotalSeconds / expectedSeconds * 94);
        progress.Value = Math.Clamp(Math.Max(observedProgress, timeBased), 1, 95);
        var remaining = TimeSpan.FromSeconds(Math.Max(0, expectedSeconds - elapsed.Elapsed.TotalSeconds));
        timeLabel.Text = $"Прошло: {FormatTime(elapsed.Elapsed)} · примерно осталось: {FormatTime(remaining)}";
    }

    private async void SaveClicked(object? sender, EventArgs e)
    {
        if (resultZip is null || !File.Exists(resultZip)) return;
        var sourceArchive = resultZip;
        isExporting = true;
        saveButton.Enabled = false;
        startButton.Enabled = false;
        extendedButton.Enabled = false;
        openFolderButton.Enabled = false;
        var previousStatus = statusLabel.Text;
        statusLabel.Text = "Сохранение ZIP в папку Загрузки…";
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
            var destination = await Task.Run(async () =>
                await ArchiveExporter.CopyToDirectoryAsync(sourceArchive, ArchiveExporter.GetDefaultExportDirectory(), timeout.Token), timeout.Token);
            statusLabel.Text = "ZIP сохранён: " + destination;
            MessageBox.Show(this, "Архив сохранён:\r\n" + destination,
                "Traffic Lab", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (OperationCanceledException)
        {
            statusLabel.Text = previousStatus;
            MessageBox.Show(this, "Сохранение ZIP превысило 2 минуты. Проверьте доступность папки Загрузки и свободное место.",
                "Traffic Lab", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        catch (Exception ex)
        {
            statusLabel.Text = previousStatus;
            MessageBox.Show(this, "Не удалось сохранить ZIP:\r\n" + ProgramAccess.Redact(ex.Message),
                "Traffic Lab", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            isExporting = false;
            saveButton.Enabled = resultZip is not null && File.Exists(resultZip);
            openFolderButton.Enabled = saveButton.Enabled;
            startButton.Enabled = !isRunning;
            extendedButton.Enabled = !isRunning;
        }
    }

    private void OpenFolderClicked(object? sender, EventArgs e)
    {
        if (resultZip is null) return;
        Process.Start(new ProcessStartInfo("explorer.exe") { UseShellExecute = true, ArgumentList = { "/select,", resultZip } });
    }

    private void OnClosing(object? sender, FormClosingEventArgs e)
    {
        if (!isRunning && !isExporting) return;
        var message = isRunning
            ? "Тест ещё выполняется. Используйте STOP TEST и дождитесь завершения очистки."
            : "Архив ещё сохраняется. Дождитесь завершения копирования.";
        MessageBox.Show(this, message, "Traffic Lab", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        e.Cancel = true;
    }

    private static string FormatTime(TimeSpan value) => $"{(int)value.TotalHours:00}:{value.Minutes:00}:{value.Seconds:00}";
}

internal static class ProxyConflictDetector
{
    private static readonly Regex ProxyProcess = new(@"^(xray|v2ray|v2rayn|sing-box|clash|clash-verge|hiddify|nekoray|shadowsocks|outline|openvpn|wireguard|wg|tailscale|zerotier|warp-svc|psiphon|tor)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static IReadOnlyList<string> Scan()
    {
        var findings = new List<string>();
        var environment = Program.CaptureNetworkEnvironmentForCommands();
        if (environment.WindowsSystemProxyEnabled) findings.Add("включён системный Windows proxy" + (string.IsNullOrWhiteSpace(environment.WindowsSystemProxyServer) ? "" : $" ({environment.WindowsSystemProxyServer})"));
        if (environment.WindowsAutoConfigUrlPresent) findings.Add("настроен PAC/AutoConfig URL");
        foreach (var name in environment.PotentialTunnelInterfaces) findings.Add($"активен возможный VPN/TUN-интерфейс: {name}");
        foreach (var variable in new[] { "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY" }.Where(name => !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(name)))) findings.Add($"задана переменная окружения {variable}");

        // A proxy executable or a loopback listener alone cannot affect Traffic Lab's
        // direct requests. Clients sometimes leave an orphaned xray/sing-box process
        // behind after disconnecting. Only report these as supporting details when a
        // system proxy, PAC, proxy environment variable, or VPN/TUN route is active.
        if (findings.Count == 0) return [];

        try
        {
            var commonProxyPorts = new HashSet<int> { 1080, 2080, 3128, 7890, 7891, 8080, 8888, 10808, 10809, 20170 };
            foreach (var listener in IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Where(item => commonProxyPorts.Contains(item.Port)))
                findings.Add($"открыт типичный локальный proxy-порт {listener.Address}:{listener.Port}");
        }
        catch { }
        try
        {
            foreach (var process in Process.GetProcesses())
            {
                using (process)
                {
                    if (process.Id != Environment.ProcessId && ProxyProcess.IsMatch(process.ProcessName)) findings.Add($"запущен процесс {process.ProcessName} (PID {process.Id})");
                }
            }
        }
        catch { }
        return findings.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }
}
