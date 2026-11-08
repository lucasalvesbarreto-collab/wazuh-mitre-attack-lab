# Índice de evidências

Prints do dashboard Wazuh (rodada de 07/11/2026), organizados por técnica em
`tecnicas/<técnica>/evidencias/`.

## T1110 Brute Force

| Arquivo | Mostra |
|---|---|
| `T1110-01-100110-8-falhas.png` | 8 falhas na mesma conta e a 100110 expandida |
| `T1110-02-negativo-3-falhas.png` | Teste negativo: 3 falhas, sem a 100110 |
| `T1110-03-falhas-seguidas-de-logon.png` | 100110 seguida do logon correto (100112) |
| `T1110-04-spray-100111.png` | Spray a partir do Ubuntu e a 100111 |
| `T1110-05-spray-logon-100112-sobreposicao.png` | Spray seguido de logon: a 100112 vence a 100113 |

## T1136.002 Create Account: Domain Account

| Arquivo | Mostra |
|---|---|
| `T1136.002-01-net-user-add.png` | `net user /add`: 100120 e 100121 |
| `T1136.002-02-negativo-alteracao-60110.png` | Teste negativo: alteração de conta, só a 60110 |
| `T1136.002-03-new-aduser-so-100120.png` | `New-ADUser`: só a 100120, sem a 100121 |

## T1098 Account Manipulation

| Arquivo | Mostra |
|---|---|
| `T1098-00-criacao-svc-antiga.png` | Criação da conta antiga usada no teste negativo |
| `T1098-01-visao-geral.png` | Visão geral dos testes |
| `T1098-02-admins-local.png` | 100122 e 100123: promoção a Administradores local |
| `T1098-03-domain-admins-sem-correlacao-13min.png` | 100125 sem 100126: janela de 10 min expirada |
| `T1098-04-cadeia-completa.png` | 100120 → 100124 e 100120 → 100126 |
| `T1098-05-100124-detalhe.png` | 100124 expandida |
| `T1098-06-100126-detalhe.png` | 100126 expandida |

## T1059.001 PowerShell

| Arquivo | Mostra |
|---|---|
| `T1059.001-01-base64-100130-100135.png` | Cadeia Base64: 100130 e 100134 |
| `T1059.001-03-bypass-100131.png` | `-ExecutionPolicy Bypass` (100131) |
| `T1059.001-04-iex-100132.png` | `Invoke-Expression` no ScriptBlock (100132) |
| `T1059.001-05-download-100133.png` | Download via `Net.WebClient` (100133) |
| `T1059.001-06-ruido-92213.png` | 92213 expandida: `__PSScriptPolicyTest` em `targetFilename` |
| `T1059.001-07-cmd-100135.png` | `cmd.exe` → `powershell.exe -enc`: 100135 |
