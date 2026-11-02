# 第 1 道盾：主机、网络与云账号

服务器层的事大多要登录云控制台或生产服务器操作。AI 只出清单和命令，**由用户本人执行，或在用户当次明确授权后执行**；执行前先备份配置，执行后回读核实。

## 1. 云安全组（最外层）

| 端口 | 对谁开 |
|---|---|
| 80 / 443 | 公网 |
| 3389（远程桌面）/ 22（SSH）/ 面板端口 | 只对运维白名单 IP，或只走私网（WireGuard 等） |
| 数据库（1433 / 3306 / 5432 / 自定义端口） | 只对应用服务器内网地址；必须跨公网时限定来源 IP 并开传输加密 |
| 其他（8080、5000、调试端口） | 不开。开发期临时开的，上线前关掉 |

验收：从办公网以外的地方 `Test-NetConnection <IP> -Port <端口>` 或 `nc -vz <IP> <端口>`，除 80/443 外都不通。

**出站也要收口**（安全组的出站方向）：只放行支付、短信、微信、对象存储、AI 服务、系统更新等必要地址，拦掉云厂商元数据地址的非必要访问。这样即使某处有 SSRF 或命令注入，攻击者的带外回连、下载木马、外传数据都打不出去。允许的出站地址写进安防档案的"出站连接清单"。收口前先从访问日志和应用配置里把必要地址列全，否则会断掉正常业务。

**测绘平台视角**：没有 CDN 时，FOFA、鹰图、Quake、Shodan 能按网站图标、标题、证书直接查到源站 IP 和所有开放端口。每季度去这些平台搜一次自家图标和标题，看暴露了什么。后台可以考虑和官网用不同的图标和标题，再加 IP 白名单或只走 VPN（加分项，不能替代鉴权）。

## 2. 主机防火墙

- **先确认它真的开着。** 参考项目的生产机三个配置文件全是关闭的，加的封禁规则一条都不生效，靠云安全组挡端口、靠 IPsec 封 IP。
  - Windows：`Get-NetFirewallProfile | Select Name, Enabled`
  - Linux：`ufw status verbose` / `nft list ruleset`
- 开启防火墙是高风险操作（规则没配好会把自己的远程连接断掉）。要做的话：先放行远程管理端口和 80/443，再开启；在云控制台准备好"救援登录"再动手。是否开启由用户决定。
- 防火墙关着时封 IP 用 IPsec 静态策略，命令见 `ip-ratelimit-blocking.md` §4.1。

## 3. 远程登录

- SSH 只用密钥（ed25519），禁用密码登录；Windows OpenSSH 的 `administrators_authorized_keys` 权限只留 Administrators 和 SYSTEM。
- Linux：`PermitRootLogin no`、`PasswordAuthentication no`，fail2ban 守 sshd。
- 远程桌面开网络级别身份验证（NLA），账户锁定策略；能走私网就不对公网开。
- 运维文档不存任何密码。
- 装机时临时开的代理工具，用完关掉（至少关 TUN 模式）。

## 4. Web 服务器加固

### 4.1 IIS

主站 `web.config`（发版脚本生成时一并写入）：

```xml
<system.webServer>
  <security>
    <requestFiltering removeServerHeader="true">
      <requestLimits maxAllowedContentLength="115343360" />
      <hiddenSegments>
        <add segment=".git" />
        <add segment=".env" />
      </hiddenSegments>
    </requestFiltering>
  </security>
  <httpProtocol>
    <customHeaders>
      <remove name="X-Powered-By" />
      <add name="X-Content-Type-Options" value="nosniff" />
      <add name="X-Frame-Options" value="SAMEORIGIN" />
      <add name="Referrer-Policy" value="strict-origin-when-cross-origin" />
    </customHeaders>
  </httpProtocol>
  <directoryBrowse enabled="false" />
  <modules><remove name="WebDAVModule" /></modules>
</system.webServer>
```

- **隐藏路径段和应用层蜜罐二选一**：IIS 在请求进入应用之前就对隐藏路径段回 404.8，应用里的蜜罐中间件根本看不到这些请求，命中即封不会触发。保底、基础档用上面的隐藏路径段即可；正常档起做了蜜罐封禁的，把 `.git`、`.env` 从隐藏路径段里拿掉，交给封禁中间件处理（命中即封、回 404），或者让自动封禁直接从 IIS 日志里取 `404 8` 的记录。两种做法的前提都是：这些文件本来就不在网站目录里。
- 响应头在应用里加（`dotnet-patterns.md` §8）还是在 web.config 加，二选一，别两边都加出重复值。
- 移除 WebDAV（否则 PUT / DELETE 可能被它截走）。
- 动态 IP 限制：见 `ip-ratelimit-blocking.md` §3。
- 检查所有站点和绑定：停用的旧站点删掉或至少保持停止，确认没人会重新启动；多余端口绑定（如 8080）移除。
- TLS：禁用 TLS 1.0 / 1.1 和弱加密套件（IIS Crypto 工具或注册表），改前备份注册表、改后重启验证。
- **关闭 8.3 短文件名**：攻击工具（shortscan、IIS_shortname_Scanner）能利用 IIS 对 `~1` 的处理差异猜出目录里的文件名。`fsutil behavior set disable8dot3 1` 关掉新文件的短名，再对网站和上传目录执行 `fsutil 8dot3name strip /s /v <目录>` 清掉已有短名（先在测试机试，改的是文件系统行为）；请求筛选里拒绝含 `~` 的地址。改完用 shortscan 扫自己验证。
- 请求筛选隐藏 `.git`、`.env`、`.map` 等路径段（与蜜罐的取舍见上文）；上传目录禁止执行任何处理程序。

### 4.2 nginx

```nginx
server_tokens off;
client_max_body_size 110m;
add_header X-Content-Type-Options nosniff always;
add_header X-Frame-Options SAMEORIGIN always;
add_header Referrer-Policy strict-origin-when-cross-origin always;
add_header Strict-Transport-Security "max-age=31536000" always;  # 确认所有子域都支持 HTTPS 后再加 includeSubDomains
location ~ /\.(?!well-known) { deny all; }
ssl_protocols TLSv1.2 TLSv1.3;
```

限速见 `ip-ratelimit-blocking.md` §3。

## 5. HTTPS 证书

- 全站 HTTPS，HTTP 301 跳 HTTPS，HSTS（`max-age` 至少 1 年；确认所有子域都支持 HTTPS 后再加 `includeSubDomains`）。
- **证书链要完整**：服务器要把中间证书（必要时连同交叉证书）一起发出去。浏览器会自己补链，第三方服务器（微信支付、公众号回调等）不会——链不全时对方在 TLS 握手阶段就拒绝，你的访问日志里一行痕迹都没有，几乎查不出来。验证：`openssl s_client -connect 域名:443 -servername 域名 -showcerts`，数一下发出的证书张数并核对签发关系。
- 能自动续期就自动续期（win-acme、certbot）；买的证书在档案里写到期日，提前 30 天提醒。
- 换证书时把"补交叉证书 / 中间证书"写进换证步骤，不靠记忆。

## 6. 数据库连接

- 应用账号最小权限：业务账号不用 sa / root / db_owner；只读用途（报表、分析、对账、只读核对）单独建只读账号。
- 数据库尽量只在内网可达。必须走公网时：来源 IP 白名单 + 传输加密（`Encrypt=True`，且配置可信证书，不用 `TrustServerCertificate=True` 跳过校验）。
- 不同系统用不同账号，出事能区分是谁写的，也能单独吊销。

## 7. 旧系统与多余入口

- 换了新系统后，旧系统要**整站下线**，只保留一个跳转到新站的空壳。只把首页或注册页跳转走是不够的：参考项目的旧官网 `/Register/Index` 已经跳到新站，但注册提交、找回密码、发验证码的处理方法还都能调用，被拿来批量注册。
- 下线后逐个核验旧系统的提交接口：故意提交错误数据，看是不是 404。
- 不在自己服务器上的旧系统（同事、外包、供应商维护），把要求和核验方法写清楚交给对方，并在档案里记负责人。

## 8. 补丁与依赖

- 操作系统、IIS / nginx、.NET / Node 运行时：开启自动安全更新，或每月固定一次。
- 应用依赖漏洞扫描见 `data-release-ops.md` §6。

## 9. 云账号、域名与邮件

控制台被接管，前面所有的盾都被绕过：对方可以直接改安全组、重置服务器密码、删快照、改 DNS 把流量引走、改支付回调地址。这一节的操作都在各平台控制台里做，AI 只出清单，由用户本人执行。

**要保护的账号**（逐个列进档案"云账号与控制台清单"）：云主账号、域名注册商、DNS 服务商、短信平台、支付商户平台、公众号 / 小程序后台、企业微信管理员、代码仓库管理员、AI 模型平台。

1. 全部开多因素验证（动态口令或安全密钥）；绑定的手机号和邮箱是公司可控的，不是某个已离职员工的。
2. 云主账号只用来管子账号和账单，不日常登录。日常操作用子账号（腾讯云 CAM、阿里云 RAM），按最小权限授权：开发只读、运维管服务器、财务只看账单。
3. 访问密钥（AccessKey / SecretId）：不放进代码和服务器上的配置文件，服务器访问云资源优先用实例角色；必须用密钥的，权限限到具体资源，定期轮换；离职当天停用其名下的子账号和密钥。
4. 云操作审计（腾讯云云审计、阿里云操作审计）开启，对这几类操作告警：改安全组、新建访问密钥、重置实例密码、删快照或备份、改 DNS。
5. 域名：注册商开启"禁止转移"锁；域名到期自动续费并有提醒。

**DNS 记录清单与子域名接管**

- 所有 DNS 记录写进档案：记录名、指向、用途、负责人。
- 记录指向的资源（测试站、对象存储、CDN、第三方帮助中心、已释放的云服务器 IP）被删掉、记录却还在，就是"悬空记录"。别人如果能申请到同名资源，或者拿到了被回收的那个 IP，你的子域名就归他了：可以挂钓鱼页，还能种对主站生效的同站 Cookie（`SameSite` 把子域算作同站）。
- 规矩：下线资源时**先删 DNS 记录，再释放资源**；体检时逐条核对每条记录指向的资源都还在。能不能被抢注取决于服务商，不去赌，悬空的一律删。
- CAA 记录（正常档起）：只允许自己用的证书机构签发，例如 `0 issue "letsencrypt.org"`。

**邮件域名防冒充**

没有配置时，任何人都能以"@你的域名"给客户发"续费""账号异常"的钓鱼邮件。

| 记录 | 发邮件的域名 | 不发邮件的域名 |
|---|---|---|
| SPF（TXT） | `v=spf1 include:<邮件服务商> -all` | `v=spf1 -all` |
| DKIM | 在邮件服务商后台生成，按要求加 TXT | 不需要 |
| DMARC（`_dmarc` TXT） | 先 `v=DMARC1; p=none; rua=mailto:<收报告邮箱>` 观察两周，再改 `quarantine`，最后 `reject` | `v=DMARC1; p=reject` |

## 10. 流量型攻击与黑洞

前面的限速、封禁都运行在服务器上，只对"请求能到达服务器"的攻击有效。流量型攻击（大流量打满带宽）不一样：云厂商给每台服务器的公网 IP 提供免费的基础防护，流量超过阈值时会把这个 IP **整体拉进黑洞**，几个小时内所有访问都到不了，包括正常用户和支付回调。

- **正常档**：在云控制台查清本机的基础防护阈值和黑洞解封时长，写进档案；切换预案写进档案：开通高防 IP 或 CDN 的步骤和负责人，DNS TTL 平时就调低（如 600 秒）以便快速切换。云厂商的自助解封通常有次数限制，不要反复解封。
- **切换以后**必须同步做三件事：取访客 IP 的方法改为只认可信代理（`ip-ratelimit-blocking.md` §1）；源站安全组只放行高防或 CDN 的回源地址；源站 IP 已经暴露过的换一个新 IP，否则攻击者直接打老 IP。
- **极度档**：常态接入高防或 CDN，源站 IP 不对外暴露。
- 应用层的 CC 攻击（大量看似正常的请求）仍按 `ip-ratelimit-blocking.md` §3 的全站频率兜底处理。

## 11. 主机入侵发现

前面的检测都在 HTTP 层。如果上传被绕过落了后门文件，或者远程桌面被爆破进来，HTTP 日志里看不出来。这一节解决"被入侵后能不能发现"。

**基础档：防护软件真的开着**

- Windows：`Get-MpComputerStatus | Select RealTimeProtectionEnabled, AntivirusSignatureLastUpdated`；排除项 `Get-MpPreference | Select ExclusionPath, ExclusionProcess, ExclusionExtension`——攻击者进来后常把自己的目录加进排除项，排除项要定期审查、写进档案。
- 云厂商的主机安全基础版（腾讯云主机安全、阿里云云安全中心）开着，告警推到群。

**正常档：网站目录完整性比对**

- 发版脚本在解压新版后生成文件指纹清单（`Get-ChildItem -Recurse -File | Get-FileHash -Algorithm SHA256`），存在网站目录之外。
- 计划任务每 10 分钟比对一次：程序目录里出现清单外的文件、任何文件被改，或上传目录里出现 `.aspx`、`.ashx`、`.asmx`、`.config`、`.dll`、`.exe`、`.ps1`、`.bat`，立即告警。
- Linux 用 AIDE 或同样思路的脚本。

**正常档：主机关键事件告警**

| 事件 | Windows 事件 ID | 说明 |
|---|---|---|
| 远程登录失败激增 | 4625 | 远程桌面在被爆破 |
| 新建本地账号 | 4720 | 入侵后常见的留后门 |
| 加入管理员组 | 4732 | 提权 |
| 安装新服务 | 7045（系统日志） | 持久化 |
| 新建计划任务 | 4698（需开启"其他对象访问事件"审核） | 持久化 |
| 安全日志被清空 | 1102 | 清理痕迹 |

- 实现：计划任务定时用 `Get-WinEvent -FilterHashtable` 拉这些事件，推群机器人（受告警防刷约束）；或者由云主机安全代劳。
- Linux：`auth.log` / `journalctl` 的登录失败、`/etc/passwd` 与 sudoers 变化、新的 cron 和 systemd 服务。
