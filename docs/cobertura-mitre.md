# Matriz de cobertura

| Regra | Nível | Técnica | Tática | Fonte | Pai | Teste positivo | Teste negativo |
|---|---|---|---|---|---|---|---|
| 100110 | 10 | T1110.001 | Credential Access | Security 4625 | if_matched_sid 60122 | ✅ 8 falhas na mesma conta | ✅ 3 falhas não dispara |
| 100111 | 12 | T1110.003 | Credential Access | Security 4625 | if_matched_sid 60122 | ✅ spray smbclient, dispara no 6º usuário | — |
| 100112 | 14 | T1110 / T1078 | Credential Access | Security 4624 (correlação) | if_sid 60106,92657 | ✅ | ✅ logon limpo não dispara · ⚠️ vence a 100113 se houver brute force recente na mesma conta |
| 100113 | 14 | T1110 / T1078 | Credential Access | Security 4624 (correlação) | if_sid 60106,92657 (irmã da 100112) | ✅ validada | — |
| 100120 | 10 | T1136.002 | Persistence | Security 4720 | 60109 | ✅ `net user /add` e `New-ADUser` | ✅ troca de senha |
| 100121 | 10 | T1136.002 | Persistence | Sysmon 1 | sysmon_event1 | ✅ `net user /add` | ✅ `New-ADUser` não dispara |
| 100122 | 12 | T1098 | Persistence | Security 4732 (SID S-1-5-32-544) | 60154 | ✅ | ✅ conta de 58 min: só a 100122, sem correlação |
| 100123 | 10 | T1098 | Persistence | Sysmon 1 | sysmon_event1 | ✅ `net localgroup /add` | — |
| 100124 | 14 | T1098 | Persistence | Correlação 100120 → 100122 (600 s, mesmo subjectUserName) | 100122 | ✅ criou e promoveu em 2 s | ✅ promoção após 16 min não dispara |
| 100125 | 14 | T1098 | Priv. Escalation | Security 4728 (Domain Admins) | 60159 | ✅ | — |
| 100126 | 15 | T1098 | Priv. Escalation | Correlação 100120 → 100125 (600 s, mesmo subjectUserName) | 100125 | ✅ criou e promoveu em 2 s | ✅ promoção após 13 min não dispara |
| 100130 | 12 | T1059.001 | Execution | Sysmon 1 | 92057, 92027 | ✅ `-EncodedCommand` e `-ec` | ✅ `-ExecutionPolicy` não casa (testado offline) |
| 100131 | 10 | T1059.001 | Execution | Sysmon 1 | 92027 | ✅ `-ExecutionPolicy Bypass` | — |
| 100132 | 12 | T1059.001 | Execution | PowerShell 4104 | 91837 | ✅ `Invoke-Expression` | — |
| 100133 | 14 | T1059.001 | Execution | Sysmon 1 | sysmon_event1 | ✅ em processo filho (`powershell.exe -Command`) | — |
| 100134 | 14 | T1059.001 | Execution | Sysmon 1 | 100130, 100135 | ✅ `-nop -w hidden -enc` (direto e via `cmd.exe`) | — |
| 100135 | 12 | T1059.001 | Execution | Sysmon 1 (image = powershell.exe) | sysmon_event1 | ✅ `cmd.exe /c powershell -enc` (antes: sem alerta) | ✅ duplicata do `cmd.exe` eliminada pelo filtro de `image` |

> Os pais de todas as regras foram conferidos no `local_rules.xml` do manager em 07/11/2026.
> Limiares exatos da T1110: `tecnicas/T1110-brute-force/regra.xml`.

## Notas

- **Um alerta por evento:** quando uma correlação dispara (100124, 100126, 100134), a regra mãe
  (100122, 100125, 100130) não aparece: a filha mais específica a substitui.
