// Program.cs  (.NET 8 Console, non-top-level)
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace LogServer
{
    internal static class Program
    {
        // ================== 可改常量 ==================
        private static readonly int TcpPort = 17500;
        private static readonly int HttpPort = 17501;
        private static readonly bool EnableHttp = true;
        private static readonly int MaxUploadPerHour = 3;   // 0 = 不限制
        private static readonly bool UseFrp = false;  //如果Frp里没有开Proxy V2协议，这个选项还是false 
        //如果本地启动端口失败了可以重新换成别的端口再便宜|顺便改一下username吧

        // ================== 路径 ==================
        private static readonly string LogDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logtext");
        private static readonly string SelfLog = Path.Combine(LogDir, "self.log");
        private static readonly string LimitDb = Path.Combine(LogDir, "upload_limit.json");

        // ================== 计数器 ==================
        private static readonly Dictionary<string, int> Counter = new();
        private static int _currentHour = -1;

        private static void Main()
        {
            Directory.CreateDirectory(LogDir);
            LoadCounter();
            Log("MCT Log收集程序启动");

            _ = Task.Run(RunTcpAsync);
            if (EnableHttp) _ = Task.Run(RunHttpAsync);

            Thread.Sleep(Timeout.Infinite);
        }

        #region 通用工具
        private static void Log(string msg)
        {
            var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {msg}";
            Console.WriteLine(line);
            File.AppendAllText(SelfLog, line + Environment.NewLine);
        }

        private static void LoadCounter()
        {
            if (!File.Exists(LimitDb)) return;
            var json = File.ReadAllText(LimitDb);
            foreach (var kv in JsonSerializer.Deserialize<Dictionary<string, int>>(json) ?? new())
                Counter[kv.Key] = kv.Value;
        }

        private static void SaveCounter() =>
            File.WriteAllText(LimitDb, JsonSerializer.Serialize(Counter));

        private static bool CanUpload(string ip)
        {
            if (MaxUploadPerHour <= 0) return true;

            var now = DateTime.UtcNow.Hour;
            if (now != Interlocked.Exchange(ref _currentHour, now))
            {
                Counter.Clear();
                Log("[Limiter] 整点清零");
            }

            if (Counter.TryGetValue(ip, out var count) && count >= MaxUploadPerHour)
                return false;

            Counter[ip] = count + 1;
            SaveCounter();
            return true;
        }
        #endregion

        #region TCP 服务
        #region TCP 服务
        private static async Task RunTcpAsync()
        {
            var listener = new TcpListener(IPAddress.Any, TcpPort);
            listener.Start();
            Log($"[TCP] Listening on 0.0.0.0:{TcpPort}");

            while (true)
            {
                try
                {
                    using var client = await listener.AcceptTcpClientAsync();
                    string clientIp;

                    // FRPC
                    if (UseFrp)
                    {
                        var (success, realIp) = await ProxyProtocolV2Reader.TryGetRealIpAsync(client.GetStream());
                        clientIp = success ? realIp : "unknown";
                        Log($"[TCP] PROXY v2 解析结果 success={success} real-ip=>{clientIp}");
                    }
                    else
                    {
                        // 只有 UseFrp == false 时才执行
                        clientIp = ((IPEndPoint)client.Client.RemoteEndPoint!).Address.ToString();
                        Log($"[TCP] 连接 {clientIp}");
                    }

                    using var stream = client.GetStream();
                    var buffer = new byte[1024 * 64];
                    var len = await stream.ReadAsync(buffer, 0, buffer.Length);
                    var json = Encoding.UTF8.GetString(buffer, 0, len);
                    var dto = JsonSerializer.Deserialize<LogDto>(json)!;

                    // 上传频率检查
                    if (!CanUpload(clientIp))
                    {
                        Log($"[TCP] {clientIp} 已达 {MaxUploadPerHour} 次/小时，拒绝");
                        byte[] deny = Encoding.UTF8.GetBytes("LIMIT\r\n");
                        await stream.WriteAsync(deny, 0, deny.Length);
                        continue;
                    }

                    // 写文件
                    var fileName = $"{dto.Time:yyyy-MM-dd}-{dto.MachineName}.txt";
                    var filePath = Path.Combine(LogDir, fileName);
                    File.AppendAllText(filePath, dto.Content + Environment.NewLine);
                    Log($"[TCP] 追加写入 => {filePath}");

                    // 回包
                    byte[] ok = Encoding.UTF8.GetBytes("OK\r\n");
                    await stream.WriteAsync(ok, 0, ok.Length);
                }
                catch (Exception ex)
                {
                    Log($"[TCP] 异常: {ex.Message}");
                }
            }
        }
        #endregion

        #region HTTP 服务（可选）
        private static async Task RunHttpAsync()
        {
            var listener = new HttpListener();
            listener.Prefixes.Add($"http://+:{HttpPort}/");
            listener.Start();
            Log($"[HTTP] Listening on 0.0.0.0:{HttpPort}");

            const string resp = "MCT Log收集程序正在运行...";
            while (true)
            {
                try
                {
                    var ctx = await listener.GetContextAsync();
                    Log($"[HTTP] {ctx.Request.HttpMethod} {ctx.Request.Url?.AbsolutePath}");
                    var buf = Encoding.UTF8.GetBytes(resp);
                    ctx.Response.ContentType = "text/plain; charset=utf-8";
                    ctx.Response.ContentLength64 = buf.Length;
                    await ctx.Response.OutputStream.WriteAsync(buf, 0, buf.Length);
                    ctx.Response.Close();
                }
                catch (Exception ex)
                {
                    Log($"[HTTP] 异常: {ex.Message}");
                }
            }
        }
        #endregion

        private record LogDto(DateTime Time, string MachineName, string Content);

        #region PROXY Protocol v2 解析
        private static class ProxyProtocolV2Reader
        {
            private static readonly byte[] Sig =
                "\r\n\r\n\0\r\nQUIT\n"u8.ToArray(); // 12 bytes

            public static async Task<(bool success, string ip)> TryGetRealIpAsync(NetworkStream stream)
            {
                var header = new byte[16];
                if (!await ReadExactlyAsync(stream, header, 0, 16))
                    return (false, string.Empty);

                // 检查签名
                for (int i = 0; i < 12; i++)
                    if (header[i] != Sig[i])
                        return (false, string.Empty);

                int verCmd = header[12];
                if ((verCmd & 0xF0) != 0x20) // v2
                    return (false, string.Empty);

                int family = header[13] >> 4;
                int len = (header[14] << 8) | header[15];

                var payload = new byte[len];
                if (!await ReadExactlyAsync(stream, payload, 0, len))
                    return (false, string.Empty);

                // 只处理 TCP/UDP over IPv4
                if (family == 0x01 && len >= 12)
                {
                    byte[] ipBytes = new byte[4];
                    Array.Copy(payload, 0, ipBytes, 0, 4);
                    var ip = new IPAddress(ipBytes).ToString();
                    return (true, ip);
                }

                return (false, string.Empty);
            }

            private static async Task<bool> ReadExactlyAsync(NetworkStream stream, byte[] buffer, int offset, int count)
            {
                int read = 0;
                while (read < count)
                {
                    int r = await stream.ReadAsync(buffer, offset + read, count - read);
                    if (r == 0) return false;
                    read += r;
                }
                return true;
            }
        }
    }
}
#endregion
#endregion