# Simulação: T1136.002 Create Account: Domain Account

Todas as simulações foram executadas em laboratório isolado, na VM Windows `SERVER01`
(controlador de domínio primário, DomainRole=5).

## Por que T1136.002 e não T1136.001?

`SERVER01` é um Domain Controller primário. Toda conta criada nele entra diretamente no
Active Directory como conta de **domínio** — não existe banco de contas locais (SAM local)
em DCs. Portanto, a técnica correta é **T1136.002 (Domain Account)**, não T1136.001
(Local Account, aplicável a workstations e servidores membros).

## Ambiente

| Componente | Detalhe |
|---|---|
| SIEM | Wazuh (manager, indexer e dashboard) no Ubuntu Server, host `servidorubuntu` |
| Alvo | Windows Server 2022 (agente Wazuh `SERVER01`, IP `192.168.5.130`), DC primário do domínio |
| Rede | Rede interna/host-only, sem acesso externo |
| Versões | Windows Server 2022 (build 20348) · Windows PowerShell 5.1 · Sysmon coletado pelo agente Wazuh |

## Pré-requisitos

**No Windows (PowerShell como administrador)**, habilitar a auditoria de gerenciamento de contas.
Sem ela, o evento 4720 não é gerado:

```powershell
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /get /subcategory:"User Account Management"
```

Regras 100120 e 100121 instaladas no manager (`regra.xml`) e validadas:

```bash
# Ubuntu — Wazuh manager
sudo /var/ossec/bin/wazuh-analysisd -t && echo "Sintaxe OK"
sudo systemctl restart wazuh-manager
```

> **Boas práticas:** as senhas abaixo são marcadores. Use senhas de laboratório próprias
> e não as versione no repositório. Para inserir a senha sem expor no histórico:
> ```powershell
> $s = Read-Host -AsSecureString "Senha de lab"
> ```

## Método de trabalho

1. Simular **antes** de ter a regra e observar quais alertas padrão disparam
   (a regra pai foi confirmada como **60109** pelo dashboard).
2. Escrever a regra customizada como filha da regra padrão.
3. Repetir a simulação e comparar.

## Cenários

### 1. Criação com `net user /add` (espera: 100120 e 100121)

```powershell
# Em um DC, net user /add sem /domain já cria no domínio
net user svc_backup "<SENHA_DE_LAB>" /add /domain
```

O nome imita uma conta de serviço de propósito: atacantes costumam escolher nomes que
passam despercebidos em listas de contas de serviço legítimas.

### 2. Caso negativo: troca de senha de conta existente (espera: nenhuma das duas)

```powershell
net user svc_backup "<OUTRA_SENHA_DE_LAB>" /domain
```

O evento 4720 (criação) não é gerado para alteração de senha. Apenas a regra padrão
60110 (conta alterada) deve aparecer.

### 3. Criação por cmdlet PowerShell (espera: só a 100120)

```powershell
# New-ADUser cria conta no Active Directory via API (sem net.exe)
New-ADUser -Name "svc_update" `
           -SamAccountName "svc_update" `
           -AccountPassword (ConvertTo-SecureString "<SENHA_DE_LAB>" -AsPlainText -Force) `
           -Enabled $true `
           -Description "teste lab T1136.002"
```

O Sysmon não vê chamadas de API PowerShell — a 100121 não dispara. Apenas o evento 4720
no Windows Security log aciona a 100120.

## Limpeza

```powershell
# Remover as contas de domínio criadas
Remove-ADUser -Identity svc_backup -Confirm:$false
Remove-ADUser -Identity svc_update -Confirm:$false
```

Apagar e recriar a conta entre repetições: o evento 4720 só é gerado na criação.
A conta deletada não gera outro 4720 se for recriada com o mesmo nome — é um objeto novo no AD.

## Como verificar

**No dashboard do Wazuh** (ajustar o período para Last 15 minutes):

```
rule.id: (60109 or 60110 or 100120 or 100121)
```

Para confirmar que a 100121 não disparou no cenário 3:

```
rule.id: 100121
```

**Campos úteis do alerta:**

| Campo | Significado |
|---|---|
| `data.win.eventdata.targetUserName` | Conta criada |
| `data.win.eventdata.subjectUserName` | Quem criou |
| `data.win.eventdata.commandLine` | Linha de comando (alertas Sysmon, apenas 100121) |
| `data.win.system.eventID` | ID do evento Windows (deve ser 4720 nos alertas 100120) |

**Pela linha de comando no Ubuntu** (o `alerts.json` usa UTC; o dashboard mostra UTC-3):

```bash
sudo grep '"id":"100120"' /var/ossec/logs/alerts/alerts.json | tail -n 1 | python3 -m json.tool > evidencias/alerta-100120.json
sudo grep '"id":"100121"' /var/ossec/logs/alerts/alerts.json | tail -n 1 | python3 -m json.tool > evidencias/alerta-100121.json
```
