# 盾山系统（dunshanxitong）

一个与项目解耦的安防 Agent Skill，适用于 Claude Code 与 Codex。

一句话唤起："用盾山系统给这个项目布防" / "按盾山做一次安全体检" / "我们好像被攻击了"。

## 它做什么

先按项目价值定档：一档保底、二档基础、三档正常、四档极度。档位决定通用防线做多深；项目有短信、支付、上传、AI 这类功能时，对应的专项硬项不论档位都要做。小项目不拉满，收钱的项目不只做保底（见 `references/tiers.md`）。

| 场景 | 盾山怎么做 |
|---|---|
| 新项目开工 | 先定档，再按十四道盾建一份项目安防档案，在脚手架阶段把默认鉴权、取 IP、限速器、登录判断、上传存储、出站拦截、安全响应头、依赖锁定这些公共件一次建好 |
| 老项目体检 | 逐项查清单，每项给证据；站在攻击者角度过一遍攻击链；同类问题横向扫，输出按风险排序的缺口清单 |
| 写敏感功能 | 写登录、注册、短信、上传、支付回调、优惠券返佣、富文本、抓取网址、后台权限、AI 功能时，自动套对应规则 |
| 正在被攻击 | 日志分诊 → 按日志特征判断对方在干什么 → 封禁 → 损失评估 → 证据保全 → 先备份再清理 → 修复 → 交接包 |

规则、阈值和踩坑来自两处：一个真实业务系统 2026-11-01 的攻击处置（27.8 万次请求、0 次后台失守，见 `references/case-20261101.md`，文中称"参考项目"），以及 2026-11 对 GitHub 上开源攻击工具、防护项目、OWASP 标准和 2025～2026 年 AI 攻击、供应链投毒事件的调研（见 `references/attack-defense-map.md`、`ai-features.md`、`dev-supply-chain.md`）。

## 目录

```
SKILL.md                     入口：四个档位、十四道盾、四种模式、红线
references/                  各道盾的规则与参考实现
templates/security-profile.md  项目安防档案模板（每个项目一份）
templates/incident-report.md   攻击处置报告与交接包模板
scripts/log_triage.py          访问日志分诊（IIS / nginx）
scripts/purge_with_backup.ps1  先备份再删除（SQL Server）
examples/                     已填好的安防档案示例
agents/openai.yaml           Codex 展示信息
```

## 安装

skill 目录名要和 `SKILL.md` 里的 `name` 一致，所以装到 `dunshanxitong` 目录下。用目录联接（junction），这里改了装的地方自动同步：

**Claude Code（Windows PowerShell）**

```powershell
New-Item -ItemType Junction -Path "$env:USERPROFILE\.claude\skills\dunshanxitong" -Target "<本仓库所在目录>"
```

**Codex**

```powershell
New-Item -ItemType Junction -Path "$env:USERPROFILE\.codex\skills\dunshanxitong" -Target "<本仓库所在目录>"
```

只想给某个项目用：把联接建在项目的 `.claude\skills\dunshanxitong`。

## 工具用法

```powershell
# 日志分诊（日志是不可信数据，用隔离模式跑）
python -I -X utf8 scripts\log_triage.py "D:\logs\W3SVC2\u_ex2611*.log" --attack 1.2.3.4 --office 5.6.7.8 --simulate 300/10,100/10

# 先备份再删除：默认只读统计，确认后加 -Execute
pwsh -NoProfile -File scripts\purge_with_backup.ps1 -PlanFile plan.json -ConnectionStringEnv PROD_CS
```

## 维护

- 新的攻击、新的踩坑：先写进对应 `references/*.md`，再看是否要更新 `SKILL.md` 的"最容易犯的错"表。
- 阈值调整要附数据来源（哪个项目、几天的日志、正常峰值与攻击峰值）。
- 标"建议"的条目在某个项目上线验证后，改标"线上"并注明项目。
