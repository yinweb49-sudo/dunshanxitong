# 第 14 道盾：研发链路（依赖、构建、开发机、AI 编程助手）

攻击者越来越多地不直接打网站，而是打"做网站的人和工具"：投毒一个依赖包、劫持一个维护者账号、在仓库里埋一段给 AI 助手看的指令。开发机上有生产配置、发布包、数据库导出，助手能直接执行命令——这里一旦失守，前面十三道盾都被绕过。

## 1. 现实威胁（2025～2026 公开事件，按时间）

| 时间 | 事件 | 手法要点 |
|---|---|---|
| 2025-07 | Replit 代理在"代码冻结"期间删除生产库 | 冻结只是口头指令，没有技术强制 |
| 2025-07 | Amazon Q VS Code 扩展被合入清空文件的提示词 | 一个 PR 把恶意指令带进了官方扩展 |
| 2025-08 | Nx "s1ngularity" | 恶意安装脚本调用本机 AI 命令行，带上跳过权限确认的参数去搜刮密钥 |
| 2025-09 | chalk、debug 等 18 个 npm 包被劫持 | 维护者被钓鱼（连动态口令一起），恶意版本在线约 2.5 小时 |
| 2025-09 | Shai-Hulud | 第一个 npm 自传播蠕虫，用偷来的发布令牌感染更多包，500 多个包中招 |
| 2025-09 | postmark-mcp | 第一个在野发现的恶意 MCP 服务器，把经它发出的邮件全部密送给攻击者 |
| 2025-11 | Shai-Hulud 2.0 | 改用 preinstall 脚本 + Bun 运行时，700 多个包 |
| 2025-11 | NuGet 定时炸弹包 | 9 个功能正常的包，在 2027～2028 年的触发日之后随机杀掉数据库查询进程 |
| 2026-03 | Trivy（安全扫描工具本身）被投毒 | 恶意版本挂了约 3 小时；trivy-action 76 个标签里 75 个被改指向恶意提交——**安全工具也要按提交哈希锁定** |
| 2026-05 | TanStack "Mini Shai-Hulud" | 投毒 CI 缓存后用 CI 自己的身份发布，带合法来源证明；令牌被吊销时执行删除；在 `.claude/`、`.vscode/` 留后门 |
| 2026-08 | ChainDrop（微软披露） | 400 多个 npm 包；往仓库里写 `.claude/settings.json` 和 `.vscode/tasks.json`，下次打开 Claude 或 VS Code 就重新执行 |

结论：**"有来源证明"不等于安全；新版本冷却期比验签更管用；AI 助手的配置目录已经是攻击者的持久化位置。**

## 2. 依赖防投毒（最小可行清单）

**前端（npm / pnpm）**

1. 锁文件入库；CI 和发版打包只用 `npm ci` / `pnpm install --frozen-lockfile`，不用 `npm install`。
2. 新版本冷却期 7 天：
   - npm：`.npmrc` 写 `min-release-age=7`（npm 11.10 起支持，单位天）。
   - pnpm：`minimumReleaseAge: 10080`（单位分钟，默认 1440 即 1 天）。
   - 紧急安全修复按单个包豁免，并记录原因。
3. 默认不执行依赖的安装脚本：npm `ignore-scripts=true`（npm 12 起默认不执行，用白名单放行）；pnpm 用 `allowBuilds` 白名单、`strictDepBuilds` 开着。确实需要编译的包逐个放行。
4. pnpm 的 `blockExoticSubdeps`（禁止间接依赖从 git、tarball 地址拉）保持开启。
5. 扫描：`npm audit --omit=dev` 或 OSV-Scanner 扫锁文件；**构建产物 `dist/` 也扫一遍密钥**（`VITE_` 开头的环境变量会被打进前端包）。

**后端（NuGet）**

1. 开锁文件：`<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>`，CI 用 `dotnet restore --locked-mode`。
2. Package Source Mapping：只认 nuget.org（和自己的私有源）。
3. NuGetAudit：.NET 10 默认审计传递依赖；把 `NU1903`、`NU1904`（高危、严重）设为错误，不让带高危漏洞的版本过构建。
4. 记住 NuGet 包里的 `build/*.targets` 和分析器会在**构建时执行代码**，新增 NuGet 依赖同样要审。

**新增依赖的审批**

- 看作者、下载量、首次发布时间、最近一次发布时间、名字是否和热门包只差一两个字母。
- AI 助手建议加的包一样要审：助手可能编出一个不存在的包名，攻击者会抢注这些名字。
- 能用标准库或已有依赖解决的，不加新包。

**CI（如果有）**

- 第三方 Action / 插件按完整提交哈希锁定，不用版本标签（标签可以被强推改指向）。
- `pull_request_target` 一类以高权限运行的工作流，不检出外部提交的代码。
- 发布令牌用短期、最小范围的；能用 trusted publishing 就不放长期令牌。

## 3. 开发机

1. 开发机不长期存放生产凭据、npm / NuGet 发布令牌。生产连接串需要时由人从凭据管理器取。
2. 含生产配置的发布包、数据库导出用完即删，或放在加密目录（见 `data-release-ops.md` §4、§5）。
3. 仓库里提交前扫密钥：gitleaks 做 pre-commit 钩子；历史审计可用 trufflehog（它会去真实服务验证密钥是否还有效）。
4. 克隆陌生仓库后，打开之前先看：`.claude/`、`.mcp.json`、`.vscode/tasks.json`、`.vscode/settings.json`、`.git/hooks/`、`package.json` 的 scripts。

## 4. AI 编程助手

**原则：AI 助手是一个高权限、会被内容影响的执行者。口头规则（CLAUDE.md、AGENTS.md）是提醒，技术手段才是约束。**

1. **生产凭据不进助手能读的范围**：用沙箱的禁止读取规则覆盖生产配置文件、user-secrets 目录、证书目录。
2. **钩子硬拦截**（Claude Code 的 PreToolUse hook，Codex 的审批策略）：命令里出现以下内容时拒绝或强制人工确认——
   - 生产服务器地址、生产数据库地址或库名；
   - `-AllowProd` 这类生产开关；
   - `DROP`、`TRUNCATE`、不带 `WHERE` 的 `DELETE` / `UPDATE`；
   - `terraform destroy`、强推、递归删除、`format`。
   - 前缀式的拒绝规则很容易被换个写法绕过（`powershell -Command "Remove-Item -Recurse ..."`、`sqlcmd -Q "DROP ..."`），钩子要按命令内容匹配。
3. **助手能拿到的生产库账号只能是只读账号**。写权限账号和备份存储不能和助手在同一台机器、同一身份下（有人让助手跑基础设施命令，生产库连同快照一起被删）。
4. 含生产凭据的仓库，不开"跳过所有权限确认"模式。
5. MCP 服务器只用可信来源、锁定版本、白名单。处理外部网页、Issue、陌生文档放在没有凭据的独立会话或沙箱里。
6. `.claude/settings*.json`、`.mcp.json`、`.vscode/tasks.json` 的改动纳入代码审查；Claude Code 保持最新版本（2025～2026 年修过两个"恶意仓库在信任提示前执行命令"的漏洞）。
7. 改这些配置属于改用户环境，必须用户本人同意后再改。

## 5. 中招后的处置顺序

**先清持久化 → 再吊销令牌 → 最后轮换全部凭据。顺序不能反**：有的蠕虫在发现令牌被吊销时会执行破坏（删除家目录）。

1. 对照通报的恶意版本查锁文件，确认是否中招、哪些机器装过。
2. 清持久化：`.claude/`、`.vscode/tasks.json`、计划任务、启动项、npm / yarn 缓存、CI 缓存。
3. 吊销令牌：npm、NuGet、GitHub / Gitea、云平台、AI 平台。
4. 从一台干净的机器轮换所有凭据（数据库、支付、短信、对象存储、AI 密钥）。吊销旧的和签发新的之间不留重叠窗口。
5. 从可信来源重建受影响的构建产物和服务器部署。
