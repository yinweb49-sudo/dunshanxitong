# 第 2 道盾：来源识别、限速与封禁

限速、审计、封禁、风控全都建立在"这个请求是谁发的"之上。来源认错了，后面全部白做。

## 1. 真实来源 IP

**规则**

- 服务器前面没有 CDN / 反向代理 / 负载均衡时：只认 TCP 连接地址。`X-Forwarded-For`、`X-Real-IP`、`CF-Connecting-IP`、`True-Client-IP` 一律不读，这些头攻击者可以随便填。
- 前面有代理时：只信"可信代理名单"转来的头，并且源站只允许代理的回源地址访问（否则攻击者绕过代理直连源站，照样伪造）。
  - ASP.NET Core：`ForwardedHeadersOptions` 里清空默认值，只把代理地址加进 `KnownProxies` / `KnownNetworks`，`ForwardLimit = 1`。
  - Express：`app.set('trust proxy', '<代理IP或网段>')`，不要写 `true`。
  - nginx：`set_real_ip_from <代理网段>; real_ip_header X-Forwarded-For; real_ip_recursive on;`
  - IIS 动态 IP 限制的"代理模式"保持关闭，打开就会去认 `X-Forwarded-For`。
- 全站只有一个取 IP 的公共方法，IPv4 映射的 IPv6（`::ffff:1.2.3.4`）统一转成 IPv4。禁止各文件私写。
- 部署前核实服务器前到底有没有代理：看访问日志里服务端地址和客户端地址，别凭印象。将来加了 CDN，这个方法要跟着改，在公共方法的注释里写明。

**验收**

- 自动测试：带 `X-Forwarded-For: 1.2.3.4` 请求，取到的是连接地址。
- 本地实测：带伪造头登录后台，登录记录 / 审计记录里是真实地址。
- 全文搜索 `X-Forwarded-For`、`X-Real-IP`、`Forwarded`，除公共方法的注释外不应再出现。

**案例**：攻击后排查，9 个文件各自读转发头，客服反馈、领券、续费活动的限速和员工常用 IP、审计日志都可被伪造。修复后统一调用一个方法。

## 2. 接口级限速

### 2.1 参考项目线上阈值（经真实攻击检验，可作默认值）

| 接口 | 维度与阈值 | 超限表现 |
|---|---|---|
| 会员 / 代理登录 | 账号×来源 15 分钟失败 5 次要图形验证码，10 次锁 10 分钟；同来源 15 分钟失败 30 次要验证码，120 次锁 10 分钟 | 提示几分钟后再试 |
| 员工后台登录 | 同来源 10 分钟输错 20 次（不分账号）暂停；账号×来源 15 分钟输错 5 次冷静 10 分钟 | 冷静期内密码对也不放行 |
| 注册 | 同 IP 10 分钟 10 次，官网和客户端两个注册入口共用一个计数 | 操作太频繁 |
| 找回密码、找回用户名 | 同 IP 10 分钟 10 次 | 同上 |
| 查用户名是否可用 | 同 IP 10 分钟 30 次 | 同上 |
| 发短信验证码 | 同号 120 秒 1 条、每天 10 条；同 IP 每小时 5 条、每天 20 条 | 发送太频繁 |
| 短信验证码校验 | 每个码最多试 10 次，10 分钟有效，用一次作废；各入口共用尝试次数 | 验证码错误 |
| 员工端匿名接口（发短信、找回） | 同来源 10 分钟 10 次，各接口分开计 | 操作太频繁 |
| 陌生设备验证各步骤 | 按验证票据计数，不按来源（办公室十几人共用一个出口 IP） | 操作太频繁 |
| 意见反馈 | 同 IP 10 分钟 3 次 + 同用户 24 小时 10 次 | 提交过于频繁 |
| 免登录查询账号信息 | 同 IP 每小时 3 次 + 同账号每天 10 次 | 查询过于频繁 |
| 服务账号 API | 每账号每秒 60 次 | 429 |

### 2.2 设计要点

1. **每个匿名接口都要有**。按"动作 + 来源"分开计数，不同接口互不影响。新增匿名接口时，限速是验收项。
2. **双维度**：来源 + 目标（账号、手机号、用户 ID）。只按号码限挡不住"一个 IP 轮流给几十个号发短信"，只按 IP 限挡不住"多个 IP 打一个号"。
3. **登录只数失败**。办公室共用一个出口 IP，大家正常登录不应被算进去。
4. **登录成功只清"这一对"的计数，不清来源计数**。否则攻击者穿插登一次自己的号，就把来源计数洗掉了。
5. **不存在的账号照样计数**。只给真账号计数，"输几次会不会被锁"本身就能分辨账号在不在。
6. **冷却只针对"账号×来源"，不整号锁**。整号锁的话，外人知道登录名就能每隔几分钟乱输几次，把员工一直挡在门外。
7. **计数键要和数据库的比较规则一致**：库里登录名不分大小写，计数也得不分；库里比较会忽略 `\0`、尾随空格，计数键也要先去掉，否则加个尾巴就换了一个计数。
8. **贵的操作放在限速和廉价校验之后**：短信核验、外部归属地查询、AI 调用、发邮件，都排在限速判断之后。
9. **昂贵资源加全局总量上限**：短信、AI、邮件除了按来源限，再加"全站每小时 / 每天总量"熔断和告警，挡分布式多 IP 攻击。（建议，尚未经线上验证）
10. **提示统一、不给探测反馈**：一律"操作太频繁，请稍后再试"，不显示剩余次数和剩余秒数（登录锁定可以给到分钟级）。
11. **触发时写一条警告日志**，账号和 IP 可以写哈希，供告警和事后分析。
12. **实现**：单实例部署用内存计数足够，重启清零可接受（外人触发不了重启）；窗口终点存在值里、按注入的时钟判断，方便测试；多实例部署换 Redis。参考实现见 `dotnet-patterns.md`。

## 3. 全站频率兜底（服务器层）

接口级限速保证"打不进来"，全站兜底保证"打不垮"。

**IIS：动态 IP 限制**（Windows 功能 `Web-IP-Security`，不是第三方软件）

- 服务器级配置，所有站点生效。按请求频率拦，不按并发连接数拦（浏览器打开一个页面会同时发几十个请求）。代理模式关闭。
- 实测语义：同一 IP 10 秒内超过 N 次返回 403（日志记 `403 502`），**被拒的请求不计数**。所以持续猛刷时每 10 秒照样放过 N 次，停手约 10 秒自动放行。它是限速，不是封禁。
- 安装前先查各站点配置里有没有残留的 `ipSecurity` 规则：组件没装时这些规则不生效，一装就突然生效。安装前备份 IIS 配置。
- 测试用服务器本机回环地址；别从办公室测，开发机出口就是办公室 IP，一测把全办公室拦了。
- 常用命令（生产服务器 PowerShell）：
  ```powershell
  # 暂停（即时生效）
  Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/dynamicIpSecurity/denyByRequestRate' -name enabled -value False
  # 改阈值
  Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/dynamicIpSecurity/denyByRequestRate' -name maxRequests -value 100
  # 查谁被拦：先刷日志缓冲，再在站点日志里搜 " 403 502 "
  netsh http flush logbuffer
  ```

**nginx**

```nginx
limit_req_zone $binary_remote_addr zone=perip:20m rate=20r/s;
limit_req_zone $binary_remote_addr zone=auth:10m rate=30r/m;
server {
    location / { limit_req zone=perip burst=60 nodelay; }
    location ~* /(login|register|sms|captcha|password) { limit_req zone=auth burst=10 nodelay; }
}
```

**阈值怎么定**：用 `scripts/log_triage.py` 跑最近 7～14 天日志，看三组数：正常来源 10 秒峰值、搜索引擎爬虫峰值、自己人（办公室出口）峰值。阈值取在"正常最高峰值的 2 倍以上"和"攻击峰值"之间，再用 `--simulate` 看能拦下攻击的多少。

参考项目 11 天主站日志的实测数据：

| 来源 | 10 秒最多 | 60 秒最多 |
|---|---|---|
| 11-01 主攻 IP | 1441 | 6956 |
| 10-22 攻击 IP | 1039 | 6108 |
| 办公室出口 | 48 | 111 |
| 正常客户最高 | 约 50 | 约 97 |
| 必应爬虫最高 | 85 | 95 |

按"被拒不计数"模拟：10 秒 300 次能拦下主攻 IP 59%、另一个 39%；10 秒 100 次能拦下 82%、63%；两档对办公室都是 0 误伤。

## 4. IP 封禁

### 4.1 手段分层

| 层 | 手段 | 适合 | 注意 |
|---|---|---|---|
| 云厂商 | 安全组、网络 ACL、云 WAF | 大规模、长期封禁 | 规则条数有限；要控制台权限 |
| 主机 | Windows 防火墙 / IPsec 策略；Linux ufw / ipset + iptables / nftables | 应急封禁，立即生效，连 TCP 握手都不给 | **先确认防火墙真的开着** |
| Web 服务器 | IIS「IP 和域限制」、nginx `deny` | 按站点封 | 改配置可能要回收应用池 |
| 应用 | 封禁名单表 + 内存缓存 + 管道最前面的中间件 | 后台自助封禁、记命中次数、到期自动解 | 名单读取失败要放行；回环与内网永不拦 |

**Windows（防火墙全关时用 IPsec 静态策略）**

```powershell
# 先看防火墙到底开没开（三个配置文件都要看）
Get-NetFirewallProfile | Select-Object Name, Enabled

# 一次性建策略（策略名、筛选器列表名、动作名可自定）
netsh ipsec static add policy name=BlockAttackers
netsh ipsec static add filterlist name=BlockList
netsh ipsec static add filteraction name=DropAll action=block
netsh ipsec static add rule name=BlockRule policy=BlockAttackers filterlist=BlockList filteraction=DropAll
netsh ipsec static set policy name=BlockAttackers assign=yes
Set-Service PolicyAgent -StartupType Automatic; Start-Service PolicyAgent

# 加封一个 IP
netsh ipsec static add filter filterlist=BlockList srcaddr=<IP> dstaddr=me protocol=any mirrored=yes
# 查看名单
netsh ipsec static show filterlist name=BlockList level=verbose
# 整体解除
netsh ipsec static set policy name=BlockAttackers assign=no
```

`netsh` 的坑：输出是中文、按 936 编码，用英文关键字 `findstr` 筛不到；失败重试会重复添加筛选器；返回码非 0 不一定是失败，看输出内容。

**Linux**

```bash
ipset create blocklist hash:net timeout 0 2>/dev/null
iptables -C INPUT -m set --match-set blocklist src -j DROP 2>/dev/null || iptables -I INPUT -m set --match-set blocklist src -j DROP
ipset add blocklist 1.2.3.4                 # 永久
ipset add blocklist 1.2.3.0/24 timeout 3600  # 1 小时（集合需以 timeout 参数创建）
# ufw 简单场景：ufw insert 1 deny from 1.2.3.4
```

**封完必须核实**：名单回读有这个 IP、策略处于生效状态、之后的访问日志里这个 IP 再没有新请求。

### 4.2 应用层封禁名单（后台自助封禁）

参考设计（需求已定稿，尚未经线上验证）：

- 表：IP 或网段（IPv4 网段前缀 16～32）、原因（必填）、到期时间（空 = 永久；时长档 1 小时 / 1 天 / 7 天 / 永久）、操作人 ID 与姓名快照、创建时间、解封时间与解封人（不删行留痕）、命中次数、最后命中时间。生效条件：未解封且未到期。
- 拦截位置：请求管道最前面（压缩之后、静态文件之前），覆盖页面、接口、静态资源。被封访客：网页 403 纯文字"访问已被限制"；接口 403 + 统一 JSON。
- 性能：每次请求只查内存名单；本机增删立即刷新，另每 30 秒从库重载（兼容其他系统改表）；命中次数内存累计、定时写回。
- 防误封（前后端都要校验）：不能封操作人当前 IP、回环、内网地址；封员工常用 IP 要勾选确认；弹窗显示这个 IP 下注册了几个账号、其中几个付费客户。
- 权限：只给超级管理员；封禁和解封写审计（高风险级）。
- 故障兜底：名单读取失败时放行并记日志，不能因为封禁功能出错把全站拦掉；万一把自己封了，从服务器本机（回环）访问后台解封。

### 4.3 自动封禁（建议，尚未经线上验证）

动态 IP 限制只能限速。要做到"狂刷就封"，加一层自动封禁。AI 攻击代理让扫描又快又广，人工盯日志来不及，发现和处置都要自动化。

**设计：检测和处置分开**（借鉴 CrowdSec）。各处检测只产出"决策"（谁、为什么、封多久），统一写进封禁名单；执行点可以有多个：应用中间件（不依赖防火墙，首选）、IPsec、云安全组。

**触发信号**

| 信号 | 置信度 | 建议动作 |
|---|---|---|
| 命中蜜罐路径（`/.git/config`、`/.env`、`/web.config`、`/appsettings.json`、`*.map`、`elmah.axd`、`/backup.zip`，以及与本站技术栈无关的 `.php`、`.jsp`、`/actuator`、`/wp-*`） | 高：正常用户不可能访问 | 命中一次即封 |
| 参数里出现带外回连域名（`oast.*`、`dnslog`、`burpcollaborator`） | 高 | 即封 + 告警 |
| UA 是现成扫描器（`sqlmap/`、`Nikto`、`feroxbuster/`、`Fuzz Faster U Fool` 等） | 高 | 即封 |
| 同一来源 10 分钟内被限速拒绝 ≥ 50 次 | 中 | 封 |
| 登录触发来源级锁定 | 中 | 封 |
| 1 分钟内不同路径数 ≥ 100 且 404 占比过半 | 中 | 封 |
| 同一来源 1 小时注册 ≥ 5 个账号 | 中 | 封 + 告警 |

**规则**

- 时长递增：首次 1 小时，24 小时内再犯 1 天，再犯 7 天。
- 白名单：回环、内网、员工常用 IP、自己的监控和扫描机、经反向 DNS 验证的搜索引擎爬虫（UA 可以伪造，不能只看 UA）。
- 移动网络和运营商级 NAT 后面是成百上千的真实用户，对这类地址只封短时间，或只做限速不封禁。
- 蜜罐路径绝不能出现在页面链接、sitemap、robots.txt 里，否则会误封正常爬虫。IIS 默认就拦 `web.config`，要在应用层或 URL 重写里捕获才记得到；请求筛选里设成隐藏路径段的（如 `.git`、`.env`）同样到不了应用，取舍见 `server-hardening.md` §4.1。
- 每次自动封禁推一条告警（受告警防刷约束），告警里带"一键解封"入口。
- 封禁名单出错时放行并告警，不能把全站拦掉（这是"出错时默认拒绝"原则的例外：附加拦截层不能成为单点故障）。

**现成工具（不想全部自己写时）**

| 工具 | 适用 | 注意 |
|---|---|---|
| fail2ban | Linux + nginx | 成熟、低成本，推荐 |
| CrowdSec | Linux / Windows（有 MSI，能读 IIS 日志文件或事件日志） | Windows 上官方的处置组件只有 Windows 防火墙 bouncer，**防火墙关着时不生效**；可以自己写处置组件，从它的本地接口拉决策，写进应用中间件或 IPsec |
| IPBan（DigitalRuby） | Windows，默认守远程桌面、SQL Server，可配 IIS 日志正则 | 同样依赖 Windows 防火墙；默认会把封禁 IP 上报到全球库，设 `UseDefaultBannedIPAddressHandler=false` 关闭 |
| 雷池 SafeLine、BunkerWeb | 放在前面的反向代理 WAF | 只能装在 Linux 上；Windows + IIS 要多一台机器；源站必须只放行 WAF 的 IP，否则攻击者直连源站绕过 |

Windows 防火墙关着时有两个办法：一是打开防火墙但入站默认动作设为"允许"，只承载阻止规则（属于网络配置变更，由负责人决定）；二是执行点放在应用中间件或 IPsec。

**诱饵（Canarytokens）**：Thinkst Canarytokens 免费托管版可以生成假的云密钥、"账号密码.xlsx"、Windows 目录令牌，放在服务器上或配置文件里，有人碰到就发邮件告警。数据库诱饵表属于结构变更，要走迁移审批。

## 5. 告警

10-22 那次攻击打了一整天没人发现，11-01 也是下午才察觉。告警的价值不低于限速。

| 场景 | 触发 | 数据来源 |
|---|---|---|
| 注册聚集 | 同一 IP 最近 1 小时注册 ≥ 5 个账号 | 数据库注册记录（能覆盖别的系统写进来的号） |
| 登录爆破 | 任一来源触发来源级锁定 | 登录风控事件 |
| 短信异常 | 每小时发送量超过近 7 天同时段均值 3 倍，或余额低于阈值 | 短信发送记录 / 余额查询 |
| 被限速激增 | 每 10 分钟被拒请求数超过阈值 | 应用日志 / 服务器日志 |
| 后台陌生设备 | 员工在新设备通过验证 | 设备验证记录 |
| 自动封禁 | 每次自动封禁 | 封禁名单 |

- 防刷：同一类告警同一 IP 6 小时最多 1 条；全部告警每天最多 20 条；超出只记日志。攻击者可以故意触发告警来刷短信费、轰炸管理员手机。
- 渠道：企业微信 / 钉钉 / 飞书群机器人 webhook 免审核、零成本，推荐优先；短信要单独申请"通知类"模板（不能拿验证码模板发），审核 1～2 天。
- 每日安全摘要（建议）：前一天被限速最多的 IP 前 10、登录失败前 10、短信发送量、新注册量与 7 日均值对比，每天早上推一次。
- 告警分两级：立即推送（蜜罐命中、自动封禁、短信或 AI 费用超标、新增管理员或权限变更）和日报（其余）。
- **"没有日志"本身就是告警**：日志停止写入、后台任务心跳中断、告警通道本身不通，都要能发现。再配一个外部拨测（每分钟访问首页和健康检查）。
- 小团队的轻量做法：应用里建一张安全事件表，后台任务每分钟聚合一次，按阈值推群机器人。比 Wazuh、Graylog 这类需要单独 Linux 服务器、8GB 内存起步的方案合适得多。只有一个人值守、又想要检索界面的，可以看 Seq（免费版单用户，Windows 可装，与 Serilog 原生对接）。
- 安全事件要记全：输入校验失败、权限拒绝、业务步骤顺序异常（跳步）都要写，日志格式结构化，防止换行符注入伪造日志行；写日志的数据库账号只给写权限。
