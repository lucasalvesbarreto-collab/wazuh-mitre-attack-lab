# Simulação: T1059.001 Command and Scripting Interpreter: PowerShell

Todas as simulações foram executadas em laboratório isolado, na VM Windows `SERVER01`
(controlador de domínio primário, DomainRole=5), sem acesso à internet.

## Ambiente

| Componente | Detalhe |
|---|---|
| SIEM | Wazuh (manager, indexer e dashboard) no Ubuntu Server, host `servidorubuntu` |
| Alvo | Windows Server 2022 (agente Wazuh `SERVER01`, IP `192.168.5.130`), DC primário |
| Rede | Rede interna/host-only, sem acesso externo |
| PowerShell | 5.1.20348.5756 (Windows PowerShell integrado ao Windows Server 2022) |
| Sysmon | Instalado e coletado via `Microsoft-Windows-Sysmon/Operational` |

## Pré-requisitos

### No Windows (PowerShell como administrador)

Habilitar ScriptBlock Logging via registro:

```powershell
# Criar a chave se não existir
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $path -Force | Out-Null

# Habilitar log de ScriptBlock (evento 4104)
Set-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -Value 1

# Habilitar log de invocação (necessário para gerar 4104 consistentemente)
Set-ItemProperty -Path $path -Name "EnableScriptBlockInvocationLogging" -Value 1

# Confirmar
Get-ItemProperty -Path $path
```

Verificar que os canais estão no `ossec.conf` do agente
(`C:\Program Files (x86)\ossec-agent\ossec.conf`):

```xml
<!-- Sysmon — obrigatório para regras 100130, 100131, 100133, 100134 -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<!-- PowerShell ScriptBlock — obrigatório para regra 100132 -->
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

### No Ubuntu (manager)

Regras 100130–100135 instaladas e validadas:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t && echo "Sintaxe OK"
sudo systemctl restart wazuh-manager
```

## Método de trabalho

1. Executar os testes **sem** as regras customizadas e observar quais regras padrão disparam
   (identificação das regras pai).
2. Escrever as regras customizadas como filhas das regras pai observadas.
3. Repetir os testes e confirmar que as regras customizadas disparam.

**Regras pai identificadas no dashboard:**

| Regra pai | Descrição | Canal |
|---|---|---|
| 92057 | Powershell.exe spawned a powershell process which executed a base64 encoded command | Sysmon evt1 |
| 92027 | Powershell process spawned powershell instance | Sysmon evt1 |
| 91837 | Powershell executed "Get-Content -Stream or Invoke-Expression". Possible string execution as code | PS/Operational evt 4104 |

## Cenários

### Testes A, A2, A3: Base64 (espera 100130 e 100134)

```powershell
# 1. Cria o payload (comando inofensivo) em Base64. O PowerShell exige UTF-16LE (Unicode)
$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Host "T1059 teste"'))

# 2. CONFERE que a variável não está vazia. Variável não definida vira texto vazio
#    SEM AVISO e o teste "passaria" sem payload (a regra exige >= 20 caracteres Base64)
"Tamanho do payload: " + $b64.Length

if ($b64.Length -gt 20) {
    powershell.exe -NoProfile -EncodedCommand $b64     # A  -> 100130
    Start-Sleep -Seconds 20                            # separa os alertas no dashboard
    powershell.exe -nop -w hidden -enc $b64            # A2 -> 100134 (Base64 + janela oculta)
    Start-Sleep -Seconds 20
    powershell.exe -ec $b64                            # A3 -> 100130 (forma curta)
}
```

| Teste | Flags | O que prova |
|---|---|---|
| A | `-NoProfile -EncodedCommand` | Nome completo da flag |
| A2 | `-nop -w hidden -enc` | Abreviação `-enc` (que a regra padrão 92057 **não** cobre) + janela oculta: a filha 100134 vence a 100130 |
| A3 | `-ec` | Abreviação mínima |

**Por que usar Base64?** Atacantes codificam o payload para contornar filtros de palavras-chave
e evitar problemas de aspas. O A2 reproduz o formato clássico de stager.

**Resultado esperado:** A e A3 geram **100130**; A2 gera **100134** (filha da 100130, portanto
mais específica). A coluna `rule.level` mostra 12 e 14.

### Testes A4 e A4b: Base64 vindo de `cmd.exe` (espera 100135 e 100134)

```powershell
if ($b64.Length -gt 20) {
    cmd.exe /c "powershell.exe -nop -enc $b64"                  # A4  -> 100135
    Start-Sleep -Seconds 20
    cmd.exe /c "powershell.exe -nop -w hidden -enc $b64"        # A4b -> 100134
}
```

O pai do PowerShell é o `cmd.exe`, não outro PowerShell. As regras padrão 92057/92027 exigem
PowerShell como pai, então sem a 100135 **nenhum alerta** é gerado (ponto cego comprovado
antes de a regra existir). Resultado esperado: **um** alerta por teste (100135 no A4, 100134 no
A4b), com `parentImage` = `cmd.exe` e `image` = `powershell.exe`.

Para conferir os campos reais no Ubuntu, parseie o JSON (não use regex): veja o script
`ver-100135.py` descrito em `docs/jornada.md`.

### Teste B — IEX / Invoke-Expression (espera: regra 100132)

```powershell
# Simula execução de código carregado dinamicamente (fileless)
$code = 'Write-Host "T1059 Lab Test B IEX"'
Invoke-Expression $code
```

Forma mais curta com alias:

```powershell
IEX 'Write-Host "T1059 Lab Test B IEX alias"'
```

**Por que IEX é perigoso?** É o mecanismo central do ataque fileless: o payload é baixado
como string de um C2, nunca escrito em disco, e executado diretamente com `IEX`.
O evento 4104 (ScriptBlock Logging) captura o conteúdo real do bloco de código executado,
inclusive depois de desofuscação — esse é o maior valor do canal PowerShell/Operational.

**Resultado esperado:** regra 91837 (pai) e 100132 (filha) disparam no Wazuh.

### Teste C: download via Net.WebClient (espera 100133)

```powershell
# O download roda num powershell.exe FILHO (processo novo), para o Sysmon gerar o evento 1
powershell.exe -Command "try { (New-Object Net.WebClient).DownloadString('http://127.0.0.1:9999/t') } catch {}"
```

**Por que um processo filho?** O Sysmon evento 1 registra **criação de processo**. Chamar
`(New-Object Net.WebClient).DownloadString(...)` direto numa sessão já aberta não cria processo
e fica invisível para ele (só o evento 4104 enxerga). O loopback é só para o lab não sair para a
internet; a conexão falha, mas a linha de comando já foi registrada.

**Resultado esperado:** regra 100133 dispara.

### Teste D — -ExecutionPolicy Bypass (espera: regra 100131)

```powershell
# Flag usada por atacantes para contornar restrições de execução de scripts
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command 'Write-Host "T1059 Lab Test D"'
```

Forma abreviada (igualmente detectada):

```powershell
powershell.exe -nop -exec bypass -Command 'Write-Host "bypass test"'
```

**Por que Bypass é suspeito?** A política de execução padrão de servidores Windows é
`RemoteSigned` ou `Restricted`. Bypass significa que scripts não assinados de qualquer
origem executam sem aviso — é um pré-requisito comum de ataques.

**Resultado esperado:** regra 92027 (pai) e 100131 (filha) disparam no Wazuh.

## Limpeza

Não há artefatos persistentes a remover: os testes apenas executam comandos em memória.
Para limpar o histórico de sessão do PowerShell:

```powershell
Clear-History
```

## Como verificar

**No dashboard do Wazuh** (Last 15 minutes):

```
rule.id: (100130 or 100131 or 100132 or 100133 or 100134)
```

Para ver também as regras pai:

```
rule.id: (91837 or 92027 or 92057 or 100130 or 100131 or 100132 or 100133 or 100134)
```

**Pela linha de comando no Ubuntu:**

```bash
# Ver quais regras 1001xx dispararam e quantas vezes
sudo grep -oP '"id":"10013[0-4]"' /var/ossec/logs/alerts/alerts.json \
  | sort | uniq -c | sort -rn

# Ver o JSON completo do alerta mais recente de uma regra específica
sudo grep '"id":"100132"' /var/ossec/logs/alerts/alerts.json \
  | tail -n 1 | python3 -m json.tool > evidencias/alerta-100132.json
```

**Campos úteis nos alertas:**

| Campo | Significado | Regra |
|---|---|---|
| `data.win.eventdata.commandLine` | Linha de comando completa | 100130, 100131, 100133, 100134 |
| `data.win.eventdata.scriptBlockText` | Conteúdo do bloco PowerShell | 100132 |
| `data.win.eventdata.user` | Usuário que executou | todas |
| `data.win.eventdata.parentImage` | Processo pai | 100130, 100131, 100134 |
| `data.win.system.eventID` | ID do evento Windows | todas |
