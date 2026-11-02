# 第 5、6、7 道盾：输入输出、文件、出站调用

## 1. 注入

1. 数据库访问一律参数化：ORM 查询、`FromSqlInterpolated` / 参数化命令。禁止字符串拼接 SQL，动态排序字段走白名单映射。
   - 体检搜索：`FromSqlRaw`、`ExecuteSqlRaw`、`SqlCommand(` 后面跟字符串拼接、模板字符串里出现 `WHERE`。
   - 案例：攻击方往推广码、邀请码、支付宝账号、使用上报字段里塞了 `' OR '1'='1`、`x';--`，全部被原样当文字存进库，没有一条生效——因为全站参数化。
2. XML 解析禁用 DTD（.NET 的 `XDocument.Parse` 默认已禁），防 XXE。
3. 拼命令行、拼文件路径、拼 URL 的地方同样不能直接用用户输入：路径用 `Path.GetFileName` + 根目录校验，URL 用编码函数，命令行参数用参数数组而不是整串。
4. 请求体判空和类型校验：格式错误的 JSON 回 400，不要回 500（500 会进错误日志刷屏，也暴露"这里没判空"）。

## 2. XSS 与 HTML

### 2.1 富文本（用户或员工能写 HTML 的地方）

- 服务端白名单清洗，存库前洗一次，必要时输出前再洗一次。.NET 用 Ganss.Xss `HtmlSanitizer`；Node 用 `sanitize-html` / 服务端 DOMPurify；Python 用 `nh3` / `bleach`。
- **从空白名单开始加**，不要在默认白名单上追加。默认白名单往往放行 `form`、`input`、`button`、`textarea` 和 `action` 属性，等于允许在你的域名下放钓鱼表单。参考项目的服务详情清洗器注释写着"不含 form"，但因为只追加没清空，默认的表单标签其实都放行了。
- 不放行 `on*` 事件属性、`script`、`iframe`、`object`、`embed`、SVG 的 `foreignObject` 和 `animate` 系列；URL 协议只放 `http`、`https`、`mailto`（模板类只放 `data:`）。
- `style` 只放安全的 CSS 属性：不放 `position: fixed`、大 `z-index`、`background: url(...)`（可覆盖整页、可引外链）。
- **不要用黑名单正则代替清洗器**。案例：模板库手改 HTML 用正则 `\son[a-z]+\s*=` 拦事件属性，要求 `on` 前面有空白，`<svg/onload=...>` 直接绕过；改完的文件又在主域名下以 `text/html` 公开下发。
- 外链统一加 `target="_blank" rel="noopener noreferrer"`。

### 2.2 用户填的纯文本

- 在后台、邮件、导出里一律按纯文本渲染。React 默认转义，只要不用 `dangerouslySetInnerHTML` 就安全。
- 这是存储型 XSS 的主要目标：攻击方往发圈备注、服务单说明里塞 `<img src=x onerror=alert(document.domain)>`，赌的就是员工在后台打开时会执行。

### 2.3 前端渲染 HTML 的每一处都要有出处

| 内容来源 | 要求 |
|---|---|
| 后端已白名单清洗 | 可以直接渲染，注释里写明清洗器名字 |
| 构建期打进包的静态文件 | 可信 |
| Markdown | 渲染后再清洗（`marked` 不清洗原始 HTML），或配置为不允许原始 HTML |
| 字符串模板拼 HTML | 每个变量都转义 |
| 外部抓来的原文 | 用 `<iframe sandbox="" srcdoc>` 预览，脚本不执行 |

不要在前端把转义过的内容"解码回 HTML"再渲染，那等于绕过后端清洗。参考项目的教程渲染组件就有这个写法。

### 2.4 安全响应头

| 头 | 值 | 作用 |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | 浏览器不猜类型，上传的文件不会被当 HTML 执行 |
| `X-Frame-Options` 或 CSP `frame-ancestors` | `SAMEORIGIN` / `'self'` | 防点击劫持，后台、登录页尤其要有 |
| `Referrer-Policy` | `strict-origin-when-cross-origin`；带 token 的页面 `no-referrer` | 防 URL 里的参数外泄 |
| `Content-Security-Policy` | 后台和渲染页严格；官网先 Report-Only 观察 | 最后一道 XSS 防线 |
| `Strict-Transport-Security` | `max-age=31536000` | 强制 HTTPS |
| `Cache-Control` | 接口 `no-store` | 防敏感数据被缓存 |
| `Cross-Origin-Opener-Policy` | `same-origin` | 别的网页打开你的页面后拿不到窗口引用 |

- CSP 至少包含 `object-src 'none'`、`base-uri 'none'`（或 `'self'`）、`frame-ancestors`。
- 从外部域名加载的脚本和样式加 SRI（`integrity` 属性），第三方 CDN 被篡改时浏览器拒绝执行。官网引用的统计脚本这类无法加 SRI 的，至少用 CSP 限定来源。
- HSTS 的 `max-age` 至少一年。

实现见 `dotnet-patterns.md` §8 或 `server-hardening.md` §4。

### 2.5 Host 头

- 生产配置里 `AllowedHosts` 写死自己的域名（ASP.NET Core 默认 `*`，任何 Host 都接受）。
- 对外链接（重置密码、OAuth 回调、通知里的链接、下载地址）的域名从配置读，不从请求的 Host 头拼。

### 2.6 前端其他

- 生产构建不出 sourcemap；产物里搜一遍密钥特征、内网地址、`localhost`。
- 登录态不放 `localStorage`；仓库里写 token 到 `localStorage` 的工具函数即使没被引用也删掉，免得以后被人用上。
- 会话中途过期：请求封装层统一处理 401，跳登录并带回跳地址，回跳地址只允许站内路径（拒绝 `//`、`/\`、控制字符）。
- 只在前端遮挡的敏感字段不算脱敏，接口必须返回脱敏后的值。

## 3. 文件上传与下载

### 3.1 上传

1. **存储名由系统生成**（GUID 或内容哈希），扩展名从白名单里取，或按嗅探出的真实类型定。客户提交的原文件名只作为展示字段存库。
2. **类型白名单**：按场景定（头像只要 jpg/png/webp），并校验文件头（魔数）或实际解码一次；大小上限按场景定。不合格的立即删掉已写入的部分。
3. **SVG、HTML、XML 不当图片原样提供**：要么转成位图，要么只允许以附件下载。案例：攻击方上传了内容为 `<svg><script>alert(1)</script></svg>` 的 `a.svg`。
4. 直传对象存储时，把 Content-Type 和大小写进签名，客户端改不了；签名短时有效。类型不限的场景（客户资料包），下载时强制附件形式。
5. 上传目录放在站点目录之外；静态目录不设"未知类型也提供"。
6. **IIS 专项**：禁止上传 `.config`（IIS 会读取目录里的 `web.config`，能借它改处理规则甚至执行代码）；文件名里的 `::$DATA`（NTFS 数据流）、空字节、结尾的点和空格一律拒绝——用系统生成的文件名就天然避开了这些。
7. 图片重新编码一次（解码后再编码成 jpg / png / webp），顺带去掉元数据（拍摄位置等）和藏在图片尾部的附加数据。
8. 限制解压后的大小和文件数（压缩包、Office 文档本质都是压缩包）。

攻击者的参考资料（PayloadsAllTheThings「Upload Insecure Files」）里列的正是：SVG 里塞脚本、文件名 `../` 穿越、上传 `web.config`、NTFS 数据流、空字节——与 11-01 攻击号的上传一一对应。

### 3.2 下载与访问

1. 公开素材（文章配图、站内信图）可以走静态直链，随机文件名不可枚举。
2. **私有文件**（凭证、合同、客户资料、工单附件）只经鉴权接口下载：登录 → 权限点 → 这个文件确实属于这条业务记录 → 路径不越出根目录。对象存储用私有桶 + 服务端签发的短时链接。只靠"GUID 猜不到"不算私有。
3. 下载响应：`Content-Disposition: attachment`、`X-Content-Type-Options: nosniff`；只有确认是图片的才 `inline`。
4. 签名下载链接有有效期，签名里带用户和资源 ID，校验时逐项核对。

### 3.3 打包与解压

- 打包：压缩包条目名只用纯文件名（`Path.GetFileName`）。案例：客户上报的文件名 `../../web.config` 原样进了员工下载的压缩包，用某些解压软件会写到别的目录。
- 解压别人给的压缩包：每个条目解析成完整路径后必须仍在目标目录内（Zip Slip）；限制条目数和解压后总大小（防压缩炸弹）。

## 4. 出站调用

### 4.1 抓取用户提供的网址（SSRF）

适用：转存文章图片、按网址取图、Webhook 推送、链接预览、导入。

1. 只允许 `http` / `https`；网址长度上限；拒绝带用户名密码的网址（`user:pass@host`）。
2. **在建立连接那一刻检查目标 IP**，并直接连接检查过的那个 IP。只在请求前解析一次域名再请求，挡不住 DNS 重绑定。重定向产生的新连接同样要检查。实现见 `dotnet-patterns.md` §10。
3. 拦截范围：`0.0.0.0/8`、`10/8`、`100.64/10`、`127/8`、`169.254/16`（含云厂商元数据地址 169.254.169.254）、`172.16/12`、`192.0.0/24`、`192.168/16`、`198.18/15`、组播与保留段；IPv6 的回环、链路本地、唯一本地、组播；IPv4 映射地址先转回 IPv4 再判断；6to4（`2002::/16`）和 NAT64（`64:ff9b::/96`）里嵌着的 IPv4 也要取出来判断。
4. 出站客户端关闭系统代理（否则检查到的是代理地址），不带 Cookie。
5. 限制重定向次数（Webhook 推送直接不跟随），总超时，响应流式读取并限制大小。
6. "拦内网"开关不要做成可以在生产配置里关掉的。

### 4.2 调第三方 API

1. **不关 TLS 证书校验**。全文搜索 `ServerCertificateCustomValidationCallback`、`DangerousAcceptAnyServerCertificateValidator`、`rejectUnauthorized: false`、`verify=False`、`InsecureSkipVerify`。出现了就要有充分理由（比如对方证书域名不匹配，也只容忍这一种错误、只对白名单域名），并写进档案的已知风险。案例：参考项目三个调 AI 服务的客户端关了证书校验，而这几条通道带着 AI 密钥和云服务账号凭证。
2. 密钥放请求头，不放 URL 查询参数（URL 会进日志）。不得不放 URL 时，出站日志不记完整地址。
3. 把客户端传来的路径、模型名拼进上游地址时，先按白名单或正则校验（如只允许 `^[a-z0-9.\-]+:[a-zA-Z]+$`），防止 `../` 跳到上游其他接口还带着你的密钥。
4. 超时、重试、熔断；第三方挂了要能降级，不拖垮自己。

### 4.3 推送给客户的 Webhook

- 签名：`HMAC-SHA256(secret, "{timestamp}.{body}")`，放在请求头里，附验证示例代码；客户端按时间容差 + 常数时间比较校验。
- 推送地址提交时就校验（必须 https、不能是内网），推送时再按 §4.1 检查一次。
