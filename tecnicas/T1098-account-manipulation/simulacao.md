# Simulação: T1098 Account Manipulation

Todas as simulações foram executadas em laboratório isolado, na VM Windows `SERVER01`
(controlador de domínio primário, DomainRole=5).

## Ambiente

| Componente | Detalhe |
|---|---|
| SIEM | Wazuh (manager, indexer e dashboard) no Ubuntu Server, host `servidorubuntu` |
| Alvo | Windows Server 2022 (agente Wazuh `SERVER01`, IP `192.168.5.130`), DC primário do domínio |
| Rede | Rede interna/host-only, sem acesso externo |
| Versões | Wazuh: _preencher_ · Windows: _preencher_ · Sysmon e configuração: _preencher_ |

## Por que T1098 num Domain Controller?

Em um DC, **não existe banco de grupos locais** gerenciado pelo Windows local (SAM database):
os grupos Builtin (como Administradores/S-1-5-32-544) são gerenciados pelo AD DS.
Por isso:

- `Add-LocalGroupMember` e `Get-LocalGroup` não funcionam para grupos Builtin num DC.
- A promoção ao grupo **Administradores local** (Builtin) usa `net localgroup Administradores <conta> /add`.
- A promoção ao grupo **Domain Admins** usa `Add-ADGroupMember` com o SID do grupo.

## Pré-requisitos

**No Windows (PowerShell como administrador):**

```powershell
# Habilitar auditoria de gerenciamento de contas (necessário para eventos 4732 e 4728)
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /get /subcategory:"User Account Management"
auditpol /get /subcategory:"Security Group Management"
```

Regras 100120–100126 instaladas no manager (`regra.xml`) e validadas:

```bash
# Ubuntu — Wazuh manager
sudo /var/ossec/bin/wazuh-analysisd -t && echo "Sintaxe OK"
sudo systemctl restart wazuh-manager
```

> **Boas práticas:** as senhas abaixo são marcadores. Use senhas de laboratório próprias
> e não as versione no repositório. Para evitar expor a senha no histórico do shell:
> ```powershell
> $s = Read-Host -AsSecureString "Senha de lab"
> ```

## Cenários

### Teste 1: `net user /add` + `net localgroup Administradores /add`
**Espera:** 100120, 100121, 100123, 100124 (correlação em nível 14)

```powershell
# Criar a conta de domínio (dispara 100120 e 100121)
net user svc_lateral "<SENHA_DE_LAB>" /add /domain

# Promover ao grupo Administradores local Builtin (dispara 100122 e 100123)
# Em DC, usar net localgroup em vez de Add-LocalGroupMember
net localgroup Administradores svc_lateral /add

# Verificar
net localgroup Administradores
```

Aguardar até 30 segundos para os eventos chegarem ao dashboard.
A correlação **100124** só dispara se 100120 e 100122 ocorrerem dentro de 10 minutos
com o mesmo `subjectUserName`.

---

### Teste 2: `net user /add` + `Add-ADGroupMember Domain Admins`
**Espera:** 100120, 100121, 100125 (nível 14), 100126 (correlação nível 15)

```powershell
# Criar a conta de domínio (dispara 100120 e 100121)
net user svc_domainadmin "<SENHA_DE_LAB>" /add /domain

# Promover ao grupo Domain Admins pelo SID do domínio (dispara 100125)
# O SID do Domain Admins = <SID do domínio> + "-512"
$domSid = (Get-ADDomain).DomainSID.Value
Add-ADGroupMember -Identity ($domSid + "-512") -Members svc_domainadmin

# Verificar
Get-ADGroupMember -Identity "Domain Admins" | Select-Object SamAccountName
```

A regra 100126 (nível 15) dispara se 100120 e 100125 ocorrerem dentro de 10 minutos.

---

### Teste 3 (negativo de janela): criação, aguardar 11 min, depois promover
**Espera:** 100120, 100121 ao criar; 100125 ao promover; **100126 NÃO dispara** (janela expirada)

```powershell
# Criar a conta
net user svc_timeout "<SENHA_DE_LAB>" /add /domain

# Aguardar 11 minutos (janela da 100126 é 10 minutos)
Start-Sleep -Seconds 660

# Promover a Domain Admins — só dispara 100125, não 100126
$domSid = (Get-ADDomain).DomainSID.Value
Add-ADGroupMember -Identity ($domSid + "-512") -Members svc_timeout
```

Este teste valida que a correlação não produz falsos positivos fora da janela temporal.

---

### Teste 4 (negativo): promover conta já existente, sem criar
**Espera:** 100122 ou 100125; **100124 e 100126 NÃO disparam** (sem criação recente)

```powershell
# Usar uma conta preexistente (ex: Administrator ou outra do AD)
net localgroup Administradores <conta_existente> /add
# OU
$domSid = (Get-ADDomain).DomainSID.Value
Add-ADGroupMember -Identity ($domSid + "-512") -Members <conta_existente>
```

Confirma que as correlações só disparam quando há criação recente, não para promoções isoladas.

## Limpeza

```powershell
# Remover do Domain Admins antes de deletar a conta
$domSid = (Get-ADDomain).DomainSID.Value
Remove-ADGroupMember -Identity ($domSid + "-512") -Members svc_lateral,svc_domainadmin,svc_timeout -Confirm:$false

# Remover do grupo Administradores local
net localgroup Administradores svc_lateral /delete

# Remover as contas do domínio
Remove-ADUser -Identity svc_lateral -Confirm:$false
Remove-ADUser -Identity svc_domainadmin -Confirm:$false
Remove-ADUser -Identity svc_timeout -Confirm:$false
```

## Como verificar

**No dashboard do Wazuh** (ajustar o período para Last 15 minutes):

```
rule.id: (100120 or 100121 or 100122 or 100123 or 100124 or 100125 or 100126)
```

Para confirmar que a janela temporal funcionou corretamente no Teste 3:

```
rule.id: (100125 or 100126)
```

Espera: apenas 100125 visível para o período do Teste 3.

**Campos úteis em cada alerta:**

| Campo | Significado |
|---|---|
| `data.win.eventdata.subjectUserName` | Quem executou a ação |
| `data.win.eventdata.targetUserName` | Conta criada (nos alertas 100120/100121) |
| `data.win.eventdata.memberSid` | SID da conta promovida (nos alertas 100122/100125) |
| `data.win.eventdata.targetSid` | SID do grupo-alvo (100122: deve ser S-1-5-32-544) |
| `data.win.eventdata.commandLine` | Linha de comando (alertas Sysmon 100121/100123) |

**Pela linha de comando no Ubuntu** (o `alerts.json` usa UTC; o dashboard mostra UTC-3):

```bash
# Exportar os alertas de cada regra para evidências
for rid in 100120 100121 100122 100123 100124 100125 100126; do
  sudo grep "\"id\":\"${rid}\"" /var/ossec/logs/alerts/alerts.json \
    | tail -n 1 | python3 -m json.tool > evidencias/alerta-${rid}.json 2>/dev/null \
    && echo "Salvo: alerta-${rid}.json" || echo "Sem dados: ${rid}"
done
```
