using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

internal static class PortableCollector
{
    public static async Task<int> RunAsync(string[] args)
    {
        if (args.Contains("--self-test", StringComparer.OrdinalIgnoreCase)) return await RunSelfTestAsync();
        var bind = IPAddress.TryParse(Read(args, "--bind"), out var parsedBind) ? parsedBind : IPAddress.Any;
        var httpPort = ReadInt(args, "--http-port", 18080, 1, 65535);
        var udpPort = ReadInt(args, "--udp-port", 18081, 1, 65535);
        var dnsPort = ReadInt(args, "--dns-port", 15353, 1, 65535);
        var duration = ReadInt(args, "--duration", 0, 0, 86400);
        var answer = IPAddress.TryParse(Read(args, "--dns-answer"), out var dnsAnswer) ? dnsAnswer : null;
        var outputDirectory = Path.GetFullPath(Read(args, "--outdir") ?? "collector-artifacts");
        Directory.CreateDirectory(outputDirectory);
        var runId = $"collector-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}"[..43];
        var livePath = Path.Combine(outputDirectory, runId + ".jsonl");
        var events = new ConcurrentQueue<CollectorEvent>();
        var writeLock = new SemaphoreSlim(1, 1);
        using var cancellation = duration > 0 ? new CancellationTokenSource(TimeSpan.FromSeconds(duration)) : new CancellationTokenSource();
        ConsoleCancelEventHandler cancel = (_, eventArgs) => { eventArgs.Cancel = true; cancellation.Cancel(); };
        Console.CancelKeyPress += cancel;

        async Task LogAsync(CollectorEvent item)
        {
            events.Enqueue(item);
            await writeLock.WaitAsync();
            try { await File.AppendAllTextAsync(livePath, JsonSerializer.Serialize(item, LabCommands.JsonOptions).Replace("\r", "", StringComparison.Ordinal).Replace("\n", "", StringComparison.Ordinal) + Environment.NewLine, new UTF8Encoding(false)); }
            finally { writeLock.Release(); }
        }

        try
        {
            var http = RunHttpAsync(bind, httpPort, LogAsync, cancellation.Token);
            var udp = RunUdpEchoAsync(bind, udpPort, LogAsync, cancellation.Token);
            var dns = RunDnsAsync(bind, dnsPort, answer, LogAsync, cancellation.Token);
            Console.WriteLine($"Collector run ID : {runId}");
            Console.WriteLine($"HTTP echo       : {bind}:{httpPort}");
            Console.WriteLine($"UDP echo        : {bind}:{udpPort}");
            Console.WriteLine($"DNS authority   : {bind}:{dnsPort} answer={answer?.ToString() ?? "no-answer"}");
            Console.WriteLine($"Live event log  : {livePath}");
            Console.WriteLine(duration > 0 ? $"Stopping after {duration} seconds." : "Press Ctrl+C to stop.");
            try { await Task.WhenAll(http, udp, dns); } catch (OperationCanceledException) { }
        }
        catch (SocketException ex)
        {
            Console.Error.WriteLine("Collector bind failed: " + ex.Message);
            return 1;
        }
        finally
        {
            Console.CancelKeyPress -= cancel;
            var report = new
            {
                schemaVersion = "1.0",
                runId,
                generatedAt = DateTimeOffset.UtcNow,
                listeners = new { bind = bind.ToString(), httpPort, udpPort, dnsPort, dnsAnswer = answer?.ToString() },
                eventCount = events.Count,
                events = events.OrderBy(item => item.ReceivedAt).ToArray()
            };
            var reportPath = Path.Combine(outputDirectory, runId + ".json");
            await File.WriteAllTextAsync(reportPath, JsonSerializer.Serialize(report, LabCommands.JsonOptions), new UTF8Encoding(false));
            Console.WriteLine("Collector report: " + reportPath);
        }
        return 0;
    }

    private static async Task<int> RunSelfTestAsync()
    {
        var tcpPort = GetFreeTcpPort();
        var udpPort = GetFreeUdpPort();
        var dnsPort = GetFreeUdpPort();
        while (dnsPort == udpPort) dnsPort = GetFreeUdpPort();
        var events = new ConcurrentQueue<CollectorEvent>();
        Task Log(CollectorEvent item) { events.Enqueue(item); return Task.CompletedTask; }
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        var httpTask = RunHttpAsync(IPAddress.Loopback, tcpPort, Log, cancellation.Token);
        var udpTask = RunUdpEchoAsync(IPAddress.Loopback, udpPort, Log, cancellation.Token);
        var dnsTask = RunDnsAsync(IPAddress.Loopback, dnsPort, IPAddress.Loopback, Log, cancellation.Token);
        await Task.Delay(200);
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
        var httpBody = await http.GetStringAsync($"http://127.0.0.1:{tcpPort}/self-test");
        using var udp = new UdpClient();
        var token = Encoding.ASCII.GetBytes("collector-self-test");
        await udp.SendAsync(token, new IPEndPoint(IPAddress.Loopback, udpPort));
        using var udpTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var echo = await udp.ReceiveAsync(udpTimeout.Token);
        using var dns = new UdpClient();
        var query = DnsWire.BuildQuery("self-test.example", 1, out var queryId);
        await dns.SendAsync(query, new IPEndPoint(IPAddress.Loopback, dnsPort));
        using var dnsTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var dnsResponse = await dns.ReceiveAsync(dnsTimeout.Token);
        var records = DnsWire.ParseResponse(dnsResponse.Buffer, queryId);
        cancellation.Cancel();
        try { await Task.WhenAll(httpTask, udpTask, dnsTask); } catch (OperationCanceledException) { }
        var checks = new[]
        {
            httpBody.Contains("observedSourceIp", StringComparison.Ordinal),
            echo.Buffer.SequenceEqual(token),
            records.Any(item => item.Type == "A" && item.Value == "127.0.0.1"),
            events.Any(item => item.Protocol == "http"),
            events.Any(item => item.Protocol == "udp"),
            events.Any(item => item.Protocol == "dns")
        };
        Console.WriteLine(checks.All(item => item) ? "Traffic Lab collector self-test: PASS (6 checks)" : "Traffic Lab collector self-test: FAIL");
        return checks.All(item => item) ? 0 : 1;
    }

    private static async Task RunHttpAsync(IPAddress bind, int port, Func<CollectorEvent, Task> log, CancellationToken cancellationToken)
    {
        var listener = new TcpListener(bind, port);
        listener.Start();
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(cancellationToken);
                _ = Task.Run(async () =>
                {
                    using (client)
                    {
                        var remote = client.Client.RemoteEndPoint as IPEndPoint;
                        var stream = client.GetStream();
                        using var reader = new StreamReader(stream, Encoding.ASCII, false, 4096, true);
                        var firstLine = await reader.ReadLineAsync(cancellationToken) ?? "";
                        string? host = null;
                        while (true)
                        {
                            var line = await reader.ReadLineAsync(cancellationToken);
                            if (string.IsNullOrEmpty(line)) break;
                            if (line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase)) host = line[5..].Trim();
                        }
                        var path = firstLine.Split(' ', StringSplitOptions.RemoveEmptyEntries).ElementAtOrDefault(1) ?? "/";
                        var item = new CollectorEvent(DateTimeOffset.UtcNow, "http", remote?.Address.ToString(), remote?.Port, host, path, null, null);
                        await log(item);
                        var body = JsonSerializer.Serialize(new { observedSourceIp = item.SourceIp, observedSourcePort = item.SourcePort, host, path, receivedAt = item.ReceivedAt }, LabCommands.JsonOptions);
                        var bytes = Encoding.UTF8.GetBytes(body);
                        var header = Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {bytes.Length}\r\nConnection: close\r\n\r\n");
                        await stream.WriteAsync(header, cancellationToken);
                        await stream.WriteAsync(bytes, cancellationToken);
                    }
                }, CancellationToken.None);
            }
        }
        finally { listener.Stop(); }
    }

    private static async Task RunUdpEchoAsync(IPAddress bind, int port, Func<CollectorEvent, Task> log, CancellationToken cancellationToken)
    {
        using var udp = new UdpClient(new IPEndPoint(bind, port));
        while (!cancellationToken.IsCancellationRequested)
        {
            var packet = await udp.ReceiveAsync(cancellationToken);
            var token = packet.Buffer.Length <= 256 ? Convert.ToHexString(packet.Buffer).ToLowerInvariant() : Convert.ToHexString(packet.Buffer.AsSpan(0, 256)).ToLowerInvariant();
            await log(new CollectorEvent(DateTimeOffset.UtcNow, "udp", packet.RemoteEndPoint.Address.ToString(), packet.RemoteEndPoint.Port, null, null, packet.Buffer.Length, token));
            await udp.SendAsync(packet.Buffer, packet.RemoteEndPoint, cancellationToken);
        }
    }

    private static async Task RunDnsAsync(IPAddress bind, int port, IPAddress? answer, Func<CollectorEvent, Task> log, CancellationToken cancellationToken)
    {
        using var udp = new UdpClient(new IPEndPoint(bind, port));
        while (!cancellationToken.IsCancellationRequested)
        {
            var packet = await udp.ReceiveAsync(cancellationToken);
            var query = DnsCollectorWire.ReadQuestion(packet.Buffer);
            await log(new CollectorEvent(DateTimeOffset.UtcNow, "dns", packet.RemoteEndPoint.Address.ToString(), packet.RemoteEndPoint.Port, query.Name, null, packet.Buffer.Length, $"type={query.Type}"));
            var response = DnsCollectorWire.BuildResponse(packet.Buffer, query, answer);
            await udp.SendAsync(response, packet.RemoteEndPoint, cancellationToken);
        }
    }

    private static string? Read(string[] args, string name) { var index = Array.FindIndex(args, value => value.Equals(name, StringComparison.OrdinalIgnoreCase)); return index >= 0 && index + 1 < args.Length ? args[index + 1] : null; }
    private static int ReadInt(string[] args, string name, int fallback, int minimum, int maximum) => int.TryParse(Read(args, name), out var value) ? Math.Clamp(value, minimum, maximum) : fallback;
    private static int GetFreeTcpPort() { var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); try { return ((IPEndPoint)listener.LocalEndpoint).Port; } finally { listener.Stop(); } }
    private static int GetFreeUdpPort() { using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)); return ((IPEndPoint)udp.Client.LocalEndPoint!).Port; }
}

internal sealed record CollectorEvent(DateTimeOffset ReceivedAt, string Protocol, string? SourceIp, int? SourcePort, string? HostOrName, string? Path, int? Bytes, string? Detail);
internal sealed record DnsCollectorQuestion(string Name, ushort Type, int QuestionEnd);

internal static class DnsCollectorWire
{
    public static DnsCollectorQuestion ReadQuestion(byte[] query)
    {
        if (query.Length < 17) throw new InvalidDataException("DNS query is too short.");
        var offset = 12;
        var labels = new List<string>();
        while (offset < query.Length)
        {
            var length = query[offset++];
            if (length == 0) break;
            if (length > 63 || offset + length > query.Length) throw new InvalidDataException("Invalid DNS question name.");
            labels.Add(Encoding.ASCII.GetString(query, offset, length));
            offset += length;
        }
        if (offset + 4 > query.Length) throw new InvalidDataException("DNS question is truncated.");
        var type = (ushort)((query[offset] << 8) | query[offset + 1]);
        return new DnsCollectorQuestion(string.Join('.', labels), type, offset + 4);
    }

    public static byte[] BuildResponse(byte[] query, DnsCollectorQuestion question, IPAddress? answer)
    {
        var addressBytes = answer?.GetAddressBytes();
        var answerMatches = addressBytes is not null && ((question.Type == 1 && addressBytes.Length == 4) || (question.Type == 28 && addressBytes.Length == 16));
        using var stream = new MemoryStream();
        stream.Write(query, 0, Math.Min(question.QuestionEnd, query.Length));
        var buffer = stream.GetBuffer();
        buffer[2] = 0x84;
        buffer[3] = 0x00;
        buffer[6] = 0;
        buffer[7] = answerMatches ? (byte)1 : (byte)0;
        if (answerMatches)
        {
            stream.WriteByte(0xC0); stream.WriteByte(0x0C);
            stream.WriteByte((byte)(question.Type >> 8)); stream.WriteByte((byte)question.Type);
            stream.WriteByte(0); stream.WriteByte(1);
            stream.WriteByte(0); stream.WriteByte(0); stream.WriteByte(0); stream.WriteByte(30);
            stream.WriteByte(0); stream.WriteByte((byte)addressBytes!.Length);
            stream.Write(addressBytes);
        }
        return stream.ToArray();
    }
}
