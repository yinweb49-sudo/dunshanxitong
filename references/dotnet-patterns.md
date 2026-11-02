# 公共件参考实现（ASP.NET Core）

开工时在脚手架里一次建好，业务代码只调用，不各写一份。标"线上"的来自参考项目的生产代码，标"建议"的是本 skill 补充、尚未经线上验证的写法。其他技术栈按同样语义实现。

## 1. 取访客 IP（线上）

```csharp
/// 只认 TCP 连接地址，IPv4 映射的 IPv6 转成 IPv4。不读 X-Forwarded-For：
/// 前面没有代理时那个头谁都能填。以后加了 CDN / 反向代理，改成只认可信代理转来的地址。
public static class ClientIpHelper
{
    public static string From(HttpContext ctx)
    {
        var ip = ctx.Connection.RemoteIpAddress;
        return (ip?.IsIPv4MappedToIPv6 == true ? ip.MapToIPv4() : ip)?.ToString() ?? "";
    }
}
```

前面有代理时（建议）：

```csharp
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.KnownProxies.Clear();
    o.KnownNetworks.Clear();
    o.KnownProxies.Add(IPAddress.Parse("10.0.0.5"));   // 只写自己的代理 / CDN 回源地址
    o.ForwardLimit = 1;
});
app.UseForwardedHeaders();   // 放在管道最前面，之后 RemoteIpAddress 就是真实访客
```

测试：

```csharp
[Fact]
public void Forged_forwarded_header_is_ignored()
{
    var ctx = new DefaultHttpContext();
    ctx.Connection.RemoteIpAddress = IPAddress.Parse("::ffff:203.0.113.9");
    ctx.Request.Headers["X-Forwarded-For"] = "1.2.3.4";
    Assert.Equal("203.0.113.9", ClientIpHelper.From(ctx));
}
```

## 2. 限速器（线上，员工登录版）

窗口终点存在值里、按注入的 `TimeProvider` 判断（测试可以拨时钟）；缓存过期只负责回收内存。

```csharp
public sealed class LoginRateLimiter(IMemoryCache cache, TimeProvider time, ILogger<LoginRateLimiter> log)
{
    public const string TooFrequentMessage = "操作太频繁，请稍后再试";

    static readonly TimeSpan SourceWindow = TimeSpan.FromMinutes(10);  const int SourceLimit = 20;
    static readonly TimeSpan PairWindow = TimeSpan.FromMinutes(15);    const int PairLimit = 5;
    static readonly TimeSpan PairCooldown = TimeSpan.FromMinutes(10);
    static readonly TimeSpan ActionWindow = TimeSpan.FromMinutes(10);  const int ActionLimit = 10;

    /// 冷静期内密码对也不放行，所以在校验密码之前问
    public bool IsLoginBlocked(string source, string loginName) =>
        IsFull(SourceKey(source), SourceLimit)
        || (cache.TryGetValue<DateTimeOffset>(CooldownKey(source, loginName), out var until) && time.GetUtcNow() < until);

    /// 账号不存在也照样记，否则"会不会被冷静"能分辨账号在不在
    public void RecordLoginFailure(string source, string loginName)
    {
        if (Increment(SourceKey(source), SourceWindow) == SourceLimit)
            log.LogWarning("登录来源限速 source={Source}", source);
        var pair = PairKey(source, loginName);
        if (Increment(pair, PairWindow) < PairLimit) return;
        cache.Remove(pair);
        var until = time.GetUtcNow() + PairCooldown;
        cache.Set(CooldownKey(source, loginName), until, until);
    }

    /// 只清这一对；来源计数不清，否则攻击者穿插登自己的号就能洗掉
    public void RecordLoginSuccess(string source, string loginName) => cache.Remove(PairKey(source, loginName));

    /// 匿名接口通用：action 区分接口，各算各的
    public bool TryAcquire(string action, string source, int limit = ActionLimit)
    {
        var key = $"rl:{action}:{source}";
        if (IsFull(key, limit)) { log.LogWarning("限速 action={Action} source={Source}", action, source); return false; }
        Increment(key, ActionWindow);
        return true;
    }

    sealed class Window(DateTimeOffset end) { public DateTimeOffset End { get; } = end; public int Count; }

    int Increment(string key, TimeSpan length)
    {
        var now = time.GetUtcNow();
        if (!cache.TryGetValue<Window>(key, out var w) || w!.End <= now)
        {
            w = new Window(now + length);
            cache.Set(key, w, w.End);
        }
        return Interlocked.Increment(ref w.Count);
    }

    bool IsFull(string key, int limit) =>
        cache.TryGetValue<Window>(key, out var w) && w!.End > time.GetUtcNow() && Volatile.Read(ref w.Count) >= limit;

    // 计数键要和数据库比较规则一致：不分大小写，去掉库里比较会忽略的不可见字符
    static string Normalize(string s) => new string(s.Where(c => !char.IsControl(c)).ToArray()).Trim().ToLowerInvariant();
    static string SourceKey(string s) => $"login:source:{s}";
    static string PairKey(string s, string n) => $"login:pair:{s}:{Normalize(n)}";
    static string CooldownKey(string s, string n) => $"login:cooldown:{s}:{Normalize(n)}";
}
```

注册为单例（`AddSingleton`），计数在内存。多实例部署时把 `IMemoryCache` 换成 Redis 的 `INCR` + `EXPIRE`。

.NET 7+ 自带的 `Microsoft.AspNetCore.RateLimiting` 适合做"按来源的全站 / 分组频率兜底"，但它不区分成功失败、不支持"账号×来源"冷却，登录类仍用上面这种业务限速器。

## 3. 用户名不可见字符（线上）

```csharp
public static class LoginNameChars
{
    /// 控制字符（\0、\t）、各种空白、零宽等格式字符
    public static bool HasInvisible(string loginName) =>
        loginName.Any(c => char.IsControl(c) || char.IsWhiteSpace(c)
                           || char.GetUnicodeCategory(c) == UnicodeCategory.Format);
}
```

会员注册、员工注册、改名都调用它；保留名检查放在它之后。

## 4. 能不能签发登录态（线上）

```csharp
public partial class User
{
    /// 所有签发登录态的入口（账号密码、扫码、OAuth、客户端签名跳转、/me）都只调这一个
    public bool IsLoginBlocked() => DeletedAt != null || IsKnownAbuseSignature();
}
```

## 5. 会话 Cookie 与强制下线（线上）

```csharp
builder.Services.AddAuthentication("Admin").AddCookie("Admin", o =>
{
    o.Cookie.Name = ".App.Admin";
    o.Cookie.HttpOnly = true;
    o.Cookie.SecurePolicy = CookieSecurePolicy.Always;   // 建议显式写上
    o.Cookie.SameSite = SameSiteMode.Lax;
    o.ExpireTimeSpan = TimeSpan.FromHours(8);
    o.SlidingExpiration = true;
    o.Events.OnRedirectToLogin = ctx => { ctx.Response.StatusCode = 401; return Task.CompletedTask; };
    o.Events.OnRedirectToAccessDenied = ctx => { ctx.Response.StatusCode = 403; return Task.CompletedTask; };
    o.Events.OnValidatePrincipal = async ctx =>
    {
        // 每个请求查一次账号状态（服务里带 60 秒短缓存）：禁用、审批状态、版本号
        var id = int.Parse(ctx.Principal!.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var state = await ctx.HttpContext.RequestServices.GetRequiredService<AdminAuthService>().LoadStateAsync(id);
        var cookieVer = int.TryParse(ctx.Principal.FindFirst("tokenver")?.Value, out var v) ? v : 0;
        if (state is null || state.Disabled || cookieVer < state.TokenVersion)
        {
            ctx.RejectPrincipal();
            await ctx.HttpContext.SignOutAsync("Admin");
        }
    };
});

// 会话加密密钥放在发布目录之外，否则每次发版全员被踢
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(builder.Configuration["DataProtection:KeysPath"]!))
    .SetApplicationName("AppName");
```

## 6. 短信验证码（线上）

```csharp
// 同 IP 封顶：按号码的限制挡不住一个 IP 轮流给几十个号发
const int IpHourlyLimit = 5, IpDailyLimit = 20;

var code = RandomNumberGenerator.GetInt32(100_000, 1_000_000).ToString();   // 安全随机数

// 一次性消费用条件更新：两个入口同时验证不能都通过
var consumed = await db.PhoneCodes
    .Where(p => p.Id == record.Id && !p.Used && p.CreatedAt >= since)
    .ExecuteUpdateAsync(u => u.SetProperty(p => p.Used, true), ct) == 1;
```

全站总量熔断（建议）：在发送前查"本小时全站已发条数"（内存计数或库里 COUNT），超过阈值直接拒绝并告警。

## 7. 图形验证码（线上）

字形画成轮廓 `<path>`，SVG 源码里不出现字符本身；答案存服务端缓存，5 分钟有效，校验一次即删除（对错都删）。

```csharp
using var font = new SKFont(SKTypeface.FromFamilyName("Arial", SKFontStyle.Bold), 24);
using var glyph = font.GetTextPath(ch.ToString(), new SKPoint(x, y));
glyph.Transform(SKMatrix.CreateRotationDegrees(rotate, x, y));
sb.Append($"""<path d="{glyph.ToSvgPathData()}" fill="#{color:x6}"/>""");
```

测试断言：生成的 SVG 里不含 `<text`，也不含答案字符串。

## 8. 安全响应头（建议）

```csharp
app.Use(async (ctx, next) =>
{
    ctx.Response.OnStarting(() =>
    {
        var h = ctx.Response.Headers;
        h["X-Content-Type-Options"] = "nosniff";
        h["X-Frame-Options"] = "SAMEORIGIN";
        h["Referrer-Policy"] = "strict-origin-when-cross-origin";
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
        if (ctx.Request.Path.StartsWithSegments("/admin"))     // 后台：严格 CSP，先 Report-Only 观察一周
            h["Content-Security-Policy-Report-Only"] =
                "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'";
        return Task.CompletedTask;
    });
    await next();
});
```

HSTS 用框架自带的 `app.UseHsts()`（只在非开发环境）。IIS 下还要在 `web.config` 去掉 `X-Powered-By`，`<requestFiltering removeServerHeader="true" />`。

## 9. IP 封禁中间件（建议，对应 `ip-ratelimit-blocking.md` §4.2）

```csharp
public sealed class IpBlockList   // 单例：内存名单，本机改动立即刷新，后台任务每 30 秒从库重载
{
    volatile IReadOnlyList<(IPNetwork Net, int Id, DateTime? ExpiresAt)> _rules = [];
    public void Replace(IEnumerable<(IPNetwork, int, DateTime?)> rules) => _rules = rules.ToList();
    public int? Match(IPAddress ip, DateTime now)
    {
        if (IPAddress.IsLoopback(ip) || IsPrivate(ip)) return null;   // 回环与内网永不拦
        foreach (var r in _rules)
            if ((r.ExpiresAt is null || r.ExpiresAt > now) && r.Net.Contains(ip)) return r.Id;
        return null;
    }
    static bool IsPrivate(IPAddress ip) { /* 10/8, 172.16/12, 192.168/16, fc00::/7, fe80::/10 */ return false; }
}

app.Use(async (ctx, next) =>   // 放在压缩之后、静态文件之前
{
    var ip = ctx.Connection.RemoteIpAddress;
    var list = ctx.RequestServices.GetRequiredService<IpBlockList>();
    if (ip is not null && list.Match(ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip, DateTime.Now) is { } id)
    {
        HitCounter.Add(id);   // 内存累计，定时写回库
        ctx.Response.StatusCode = 403;
        await ctx.Response.WriteAsJsonAsync(new { code = 0, message = "访问已被限制" });
        return;
    }
    await next();
});
```

名单加载失败时保持上一份（或空名单）并记日志，不能把全站拦掉。`IPNetwork` 是 .NET 8+ 的 `System.Net.IPNetwork`。

## 10. 出站请求拦内网（建议写法，对应 `input-files-outbound.md` §4）

在**建立连接那一刻**检查解析出来的地址，能同时挡住 DNS 重绑定和重定向到内网：

```csharp
builder.Services.AddHttpClient("public-fetch", c => c.Timeout = TimeSpan.FromSeconds(15))
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
    {
        AllowAutoRedirect = true,
        MaxAutomaticRedirections = 3,
        UseCookies = false,
        ConnectCallback = async (ctx, ct) =>
        {
            var addrs = await Dns.GetHostAddressesAsync(ctx.DnsEndPoint.Host, ct);
            // 解析结果里只要有一个内网 / 保留地址就整体拒绝，连接用的就是检查过的这个地址
            if (addrs.Length == 0 || addrs.Any(IsPrivateOrReserved))
                throw new HttpRequestException("目标地址不允许访问");
            var target = addrs[0];
            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try { await socket.ConnectAsync(new IPEndPoint(target, ctx.DnsEndPoint.Port), ct); return new NetworkStream(socket, ownsSocket: true); }
            catch { socket.Dispose(); throw; }
        },
    });
// IsPrivateOrReserved：回环、10/8、172.16/12、192.168/16、169.254/16（含云厂商元数据 169.254.169.254）、
// 100.64/10、0.0.0.0/8、组播、IPv6 的 ::1、fc00::/7、fe80::/10，以及 IPv4 映射的 IPv6 先转回 IPv4 再判断
```

另外：只允许 `http` / `https`；限制响应体大小（读流时计数，超过就中止）；不把出站响应原样回给用户。

## 11. 打包下载文件名（线上）

```csharp
// 客户上报的文件名可能是 ../../web.config，进压缩包前只留纯文件名
var entryName = Path.GetFileName(upload.OriginalName.Replace('\\', '/'));
if (string.IsNullOrWhiteSpace(entryName)) entryName = $"file-{upload.Id}";
zip.CreateEntry(entryName);
```

解压别人给的压缩包时反过来：`Path.GetFullPath(Path.Combine(dest, entry.FullName))` 必须以 `dest` 开头，否则拒绝（Zip Slip）。

## 12. 生产库只读核对模式（线上）

本地需要看线上数据时，进程级只读，三层保护：

1. 启动时：只允许在开发环境开启；后台任务和启动种子全部不挂。
2. HTTP 层：除登录登出外，非 GET / HEAD / OPTIONS 请求一律 403。
3. 数据库命令层：EF Core `DbCommandInterceptor` 拦截写语句、存储过程和加锁读。

```csharp
public sealed partial class ProductionReadOnlyCommandInterceptor : DbCommandInterceptor
{
    [GeneratedRegex(@"\b(INSERT|UPDATE|DELETE|MERGE|CREATE|ALTER|DROP|TRUNCATE|EXEC|EXECUTE|GRANT|REVOKE|DENY|BACKUP|RESTORE|DBCC|INTO|UPDLOCK|XLOCK|HOLDLOCK)\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Blocked();

    static void EnsureReadOnly(DbCommand c)
    {
        if (c.CommandType != CommandType.Text || Blocked().IsMatch(c.CommandText))
            throw new InvalidOperationException("生产只读核对模式，数据库写命令已拦截");
    }
    // 在 ReaderExecuting / ScalarExecuting / NonQueryExecuting 及其 Async 版本里都调用 EnsureReadOnly
}
```

连接串由启动脚本临时注入子进程环境变量，不写进配置文件。最稳妥的做法仍是**给只读核对单独建一个只有 SELECT 权限的数据库账号**（建议）。
