# Playbook N1: execução maliciosa de PowerShell (T1059.001)

Aplica-se aos alertas **100130** (-EncodedCommand Base64), **100131** (-ExecutionPolicy Bypass),
**100132** (IEX/Invoke-Expression em ScriptBlock), **100133** (download via WebClient/DownloadString),
**100134** (Base64 com janela oculta — padrão de stager/C2) e **100135** (Base64 iniciado por processo
que não é PowerShell, como `cmd.exe` ou Office).

| Alerta | Significado | Severidade |
|---|---|---|
| 100130 | PowerShell com payload Base64 (-EncodedCommand) | Alta (nível 12) |
| 100131 | PowerShell ignorando política de execução (-ExecutionPolicy Bypass) | Média (nível 10) |
| 100132 | Invoke-Expression detectado em ScriptBlock — execução de código dinâmico | Alta (nível 12) |
| 100133 | PowerShell tentando download de arquivo/código externo | **Crítica** (nível 14) |
| 100134 | Base64 com janela oculta (-w hidden) — padrão de stager C2 | **Crítica** (nível 14) |
| 100135 | Base64 em PowerShell iniciado por outro processo (`parentImage` no alerta) | Alta (nível 12). **Crítica se o pai for Office, wscript ou serviço** |

> **Qualquer alerta 100133 ou 100134 deve ser tratado como incidente até prova em contrário.**
> Esses padrões são o mecanismo de entrega inicial dos principais frameworks de C2 (Cobalt Strike,
> Metasploit, Empire). Em um DC, o impacto potencial é máximo.

## 1. Coletar o contexto

Abra o alerta e anote:

- `agent.name` — máquina onde o PowerShell foi executado
- `data.win.eventdata.user` — usuário que executou (conta de serviço? usuário interativo?)
- `data.win.eventdata.commandLine` — linha de comando completa (alertas Sysmon)
- `data.win.eventdata.scriptBlockText` — conteúdo do ScriptBlock (alerta 100132)
- `data.win.eventdata.parentImage` — processo que invocou o PowerShell (Explorer? cmd? serviço?)
- `data.win.eventdata.parentCommandLine` — linha de comando do processo pai
- Hora exata do evento (dashboard exibe UTC-3; `alerts.json` usa UTC)

## 2. Triagem

### 2.1 O payload é legível ou ofuscado?

**Para alertas 100130 (Base64):** decodificar a linha de comando para entender o que seria executado:

```bash
# No Ubuntu — decodificar o Base64 da commandLine
echo "<string_base64>" | base64 -d | iconv -f utf-16le -t utf-8
```

Se o resultado ainda for ofuscado (concatenação de strings, `[char]`, `[convert]`), tratar como
incidente de alta prioridade — ofuscação em múltiplas camadas é característica de malware real.

**Para alertas 100132 (IEX):** ler o campo `scriptBlockText` — contém o código PowerShell
exatamente como foi executado, após desofuscação. Procurar:
- URLs (`http://`, `https://`)
- Nomes de funções maliciosas conhecidas (`Invoke-Mimikatz`, `Invoke-Empire`, `Add-Type`)
- Manipulação de memória (`[Runtime.InteropServices.Marshal]`, `VirtualAlloc`)
- Criação de processos, serviços ou tarefas agendadas

### 2.2 O processo pai faz sentido?

No alerta **100135** o pai já vem na própria description (`iniciado por ...`).

| Processo pai | Interpretação |
|---|---|
| `explorer.exe` | Usuário iniciou manualmente — mais provável interativo |
| `cmd.exe` | Chamado de script batch ou linha de comando — investigar contexto |
| `services.exe`, `svchost.exe` | PowerShell invocado por serviço — suspeito, investigar o serviço |
| `winword.exe`, `excel.exe`, `outlook.exe` | **Muito suspeito** — macro maliciosa em documento Office |
| `wscript.exe`, `cscript.exe` | Dropper via VBScript/JScript — comum em phishing |
| `java.exe`, `python.exe` | Aplicação de terceiro invocando PS — investigar qual aplicação |

### 2.3 O usuário deveria estar usando PowerShell agora?

1. É um horário comercial esperado para esse usuário?
2. Há chamado aberto que justifique administração remota ou script no DC?
3. O usuário é um administrador de sistema conhecido, ou é conta de usuário final, serviço ou conta comprometida (verificar alertas 100110–100113 de brute force recente)?

### 2.4 Há contexto de ataque anterior?

```
# No dashboard (Last 24h)
agent.name: SERVER01 and rule.id: (100110 or 100111 or 100112 or 100113 or 100120 or 100121) and @timestamp:[now-24h TO now]
```

Brute force seguido de PowerShell suspeito indica acesso não autorizado com execução de payload
— tratar como incidente ativo imediatamente.

### 2.5 Houve atividade subsequente?

Verificar no dashboard se, após o alerta de PowerShell, houve:

```
agent.name: SERVER01 and rule.id: (100120 or 100122 or 100125) and @timestamp:[now-30m TO now]
```

PowerShell seguido de criação de conta (100120) ou adição a grupo privilegiado (100122, 100125)
confirma cadeia de ataque ativa: T1059.001 → T1136.002 → T1098.

## 3. Decisão

```
                                 ┌─ Usuário/script autorizado, justificativa clara
                                 │  → Fechar como FP, registrar a causa
Alerta 100130/100131 ──────────►│
                                 ├─ Sem chamado / horário anômalo / usuário inesperado
                                 │  → Investigar (seção 4); escalar se não resolver em 15 min
                                 └─ Inconclusivo → escalar para N2 com contexto

                                 ┌─ scriptBlockText contém apenas código benigno confirmado
Alerta 100132 ─────────────────►│  → Fechar como FP, registrar
                                 └─ URL, funções maliciosas, manipulação de memória
                                    → Incidente imediato (seção 4)

Alerta 100133 ou 100134 ───────────────────────────────────────────────────────────────────►
  Tratar como incidente sem aguardar investigação completa. Isolar o host enquanto coleta evidências.
```

## 4. Resposta (PowerShell malicioso confirmado ou suspeita alta)

### 4.1 Contenção imediata

```powershell
# Em SERVER01 — encerrar sessões suspeitas de PowerShell
# Listar processos PowerShell ativos
Get-Process -Name powershell, pwsh | Select-Object Id, StartTime, MainWindowTitle

# Encerrar o processo pelo ID (substituir 1234 pelo PID real)
Stop-Process -Id 1234 -Force
```

```powershell
# Bloquear o usuário suspeito sem apagar a conta (preservar evidências)
Disable-ADAccount -Identity "<nome_do_usuario>"

# Encerrar sessões ativas do usuário
query session /server:SERVER01
logoff <id_da_sessao> /server:SERVER01
```

> **Não apagar processos ou arquivos antes de coletar evidências.** Se houver suspeita de
> malware em memória, considerar dump de memória antes de encerrar o processo.

### 4.2 Investigação

1. **Decodificar o payload** (se Base64): ver seção 2.1
2. **Ler o ScriptBlock completo** (se alerta 100132): `scriptBlockText` no JSON do alerta
3. **Verificar conexões de rede ativas** no momento do alerta:
   ```powershell
   # Em SERVER01
   Get-NetTCPConnection -State Established | Where-Object {$_.OwningProcess -eq <PID>}
   ```
4. **Verificar processos filhos** criados pelo PowerShell (Sysmon eventos 1 com `parentImage`
   contendo `powershell.exe`)
5. **Verificar arquivos criados ou modificados** nos 30 minutos em torno do evento:
   - Sysmon evento 11 (FileCreate) com `image` = `powershell.exe`
   - Diretórios suspeitos: `%TEMP%`, `%APPDATA%`, `C:\Windows\Temp`
6. **Verificar chaves de registro** modificadas (Sysmon evento 13):
   - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (persistência)
   - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` (bypass)

### 4.3 Escalar para N2

Incluir no resumo:
- Alerta(s) disparados (IDs e timestamps)
- Linha de comando decodificada (se Base64)
- Processo pai e usuário
- Resultado da busca por atividade subsequente (criação de conta, grupo privilegiado)
- Ações de contenção já tomadas
- Se há conexão de rede ativa suspeita

### 4.4 Registrar

```bash
# Ubuntu — exportar alertas para o incidente
for rid in 100130 100131 100132 100133 100134; do
  sudo grep "\"id\":\"${rid}\"" /var/ossec/logs/alerts/alerts.json \
    | tail -n 1 | python3 -m json.tool > incidente-${rid}.json 2>/dev/null
done
```

## 5. Fechamento

Classificar como:

- **Verdadeiro positivo:** PowerShell usado para execução maliciosa confirmada.
- **Falso positivo:** script de TI legítimo que usa bypass ou encoding. Registrar o processo pai
  e avaliar allowlist por `parentImage` ou caminho de script para reduzir ruído.
- **Inconclusivo:** escalar para N2.

Falsos positivos recorrentes de 100131 (Bypass) indicam que scripts de administração legítimos
devem ser revistos — o ideal é assinar scripts com certificado interno em vez de usar Bypass.

## Referências

- MITRE ATT&CK: [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1027](https://attack.mitre.org/techniques/T1027/), [T1105](https://attack.mitre.org/techniques/T1105/)
- Microsoft: [PowerShell ScriptBlock Logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)
- Evento Windows: [4104 — Script Block Logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)
- Regras e análise: `regra.xml`, `analise.md`
- Como reproduzir os cenários: `simulacao.md`
