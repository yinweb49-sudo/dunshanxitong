<#
盾山 · 先备份、再删除的攻击数据清理模板（SQL Server）
用 PowerShell 7（pwsh）运行：文件是无 BOM 的 UTF-8，Windows PowerShell 5.1 会把中文提示读成乱码（逻辑不受影响）。

默认只做"只读统计"：按计划文件逐表数行数，不改任何数据。
加 -Execute 才会真删：逐表把要删的行备份成 JSON → 行数和计划不一致就停 → 单事务按顺序删除 →
任何一步删出来的行数不一致就整体回滚 → 提交后回读核实。

计划文件（JSON，UTF-8）示例，表按"子表在前、父表在后"排：
{
  "backupDir": "C:\\incident-20261101\\purge-backup-1",
  "verifySql": "SELECT COUNT(*) FROM dbo.Users WHERE RegisterIP IN ('1.2.3.4')",
  "steps": [
    { "table": "dbo.Orders", "where": "UserId IN (SELECT Id FROM dbo.Users WHERE RegisterIP IN ('1.2.3.4'))", "expected": 13 },
    { "table": "dbo.Users",  "where": "RegisterIP IN ('1.2.3.4')", "expected": 3 }
  ]
}

铁律：
- where 子句由 AI 在只读统计后写好，计划文件和行数给用户过目，用户明确同意后才加 -Execute。
- 用户的授权只针对当时那批对象。之后新冒出来的数据，要重新统计、重新问。
- 连接串从环境变量或配置文件读取，脚本不打印连接串；目标库名会打印出来，执行前核对。

用法（控制台先切 UTF-8 再跑）：
  pwsh -NoProfile -Command 'chcp 65001 > $null; [Console]::OutputEncoding = [Text.Encoding]::UTF8; & .\purge_with_backup.ps1 -PlanFile plan.json -ConnectionStringEnv PROD_CS'
  pwsh -NoProfile -Command 'chcp 65001 > $null; [Console]::OutputEncoding = [Text.Encoding]::UTF8; & .\purge_with_backup.ps1 -PlanFile plan.json -ConfigJson ..\appsettings.Production.json -Execute'
#>
param(
  [Parameter(Mandatory = $true)][string]$PlanFile,
  [string]$ConnectionStringEnv,
  [string]$ConfigJson,
  [string]$ConfigKey = 'Default',
  [switch]$Execute
)
$ErrorActionPreference = 'Stop'

if ($ConnectionStringEnv) {
  $cs = [Environment]::GetEnvironmentVariable($ConnectionStringEnv)
} elseif ($ConfigJson) {
  $cs = (Get-Content $ConfigJson -Raw -Encoding UTF8 | ConvertFrom-Json).ConnectionStrings.$ConfigKey
}
if (-not $cs) { throw '没有拿到连接串：用 -ConnectionStringEnv 或 -ConfigJson 指定来源' }

$plan = Get-Content $PlanFile -Raw -Encoding UTF8 | ConvertFrom-Json
$conn = New-Object System.Data.SqlClient.SqlConnection $cs
$conn.Open()
try {
  "目标库：$($conn.DataSource) / $($conn.Database)"
  "模式：" + $(if ($Execute) { '执行删除（先备份）' } else { '只读统计' })

  foreach ($s in $plan.steps) {
    $c = $conn.CreateCommand()
    $c.CommandText = "SELECT COUNT(*) FROM $($s.table) WITH (NOLOCK) WHERE $($s.where)"
    $n = [int]$c.ExecuteScalar()
    $flag = if ($n -eq [int]$s.expected) { '' } else { '  <-- 与计划不一致' }
    "统计 {0,-28} 现有 {1,6} 行，计划 {2,6} 行{3}" -f $s.table, $n, $s.expected, $flag
  }
  if (-not $Execute) { return }

  New-Item -ItemType Directory -Force -Path $plan.backupDir | Out-Null
  foreach ($s in $plan.steps) {
    $c = $conn.CreateCommand()
    $c.CommandText = "SELECT * FROM $($s.table) WHERE $($s.where)"
    $dt = New-Object System.Data.DataTable
    [void](New-Object System.Data.SqlClient.SqlDataAdapter $c).Fill($dt)
    $rows = foreach ($r in $dt.Rows) {
      $o = [ordered]@{}
      foreach ($col in $dt.Columns) {
        $v = $r[$col]
        $o[$col.ColumnName] = if ($v -is [DBNull]) { $null } elseif ($v -is [byte[]]) { [Convert]::ToBase64String($v) } else { $v }
      }
      $o
    }
    $file = Join-Path $plan.backupDir (($s.table -replace '[^\w\.]', '_') + '.json')
    ConvertTo-Json @($rows) -Depth 3 | Set-Content $file -Encoding UTF8
    "备份 {0,-28} {1,6} 行 -> {2}" -f $s.table, $dt.Rows.Count, $file
    if ($dt.Rows.Count -ne [int]$s.expected) { throw "备份行数与计划不一致：$($s.table)，未删除任何数据" }
  }

  $tx = $conn.BeginTransaction()
  try {
    foreach ($s in $plan.steps) {
      $c = $conn.CreateCommand()
      $c.Transaction = $tx
      $c.CommandText = "DELETE FROM $($s.table) WHERE $($s.where)"
      $n = $c.ExecuteNonQuery()
      "删除 {0,-28} {1,6} 行" -f $s.table, $n
      if ($n -ne [int]$s.expected) { throw "删除行数与计划不一致：$($s.table)" }
    }
    $tx.Commit()
    '已提交'
  } catch {
    $tx.Rollback()
    '已整体回滚，数据未改动'
    throw
  }

  if ($plan.verifySql) {
    $c = $conn.CreateCommand()
    $c.CommandText = $plan.verifySql
    "回读核实：$($c.ExecuteScalar())（期望 0）"
  }
} finally {
  $conn.Close()
}
