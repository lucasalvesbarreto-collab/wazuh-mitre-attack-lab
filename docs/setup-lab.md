# Setup do lab

Guia para reproduzir o ambiente. As versões instaladas podem ser consultadas com
`/var/ossec/bin/wazuh-control info` (Ubuntu), `winver` (Windows) e `sysmon -c` (Sysmon).

## 1. Rede

Duas VMs na mesma rede **host-only** (ou rede interna do hipervisor), sem NAT para a internet
durante as simulações. Se precisar de internet para instalar pacotes, habilite temporariamente
e desligue antes de testar.

## 2. Wazuh (Ubuntu Server)

Instalação all-in-one pelo assistente oficial (consulte a documentação da versão atual em
https://documentation.wazuh.com):

```bash
curl -sO https://packages.wazuh.com/<versao>/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

Ao final, o script mostra a senha do usuário `admin` do dashboard — guarde num gerenciador
de senhas, **não** no repositório.

Conferir os serviços:

```bash
sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard
```

> Se o `wazuh-indexer` não subir, verifique `/etc/wazuh-indexer/certs`. No lab, certificados
> ausentes levaram à decisão de reinstalar do zero (ver `docs/jornada.md`).

## 3. Windows Server 2022 (SERVER01)

### 3.1 Agente Wazuh

Instalar o agente apontando para o IP do manager e iniciar o serviço `WazuhSvc`.
Conferir no dashboard (*Agents*) que `SERVER01` aparece como **Active**.

### 3.2 Sysmon

Instalar o Sysmon com um arquivo de configuração (ex.: a configuração da comunidade
SwiftOnSecurity ou olafhartong/sysmon-modular):

```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

### 3.3 Auditoria

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
```

### 3.4 PowerShell ScriptBlock Logging

```powershell
.\config\habilitar-scriptblock-logging.ps1
```

### 3.5 Canais no agente

Adicionar o conteúdo de `config/agent-localfile.xml` ao
`C:\Program Files (x86)\ossec-agent\ossec.conf` e reiniciar o agente:

```powershell
Restart-Service WazuhSvc
```

## 4. Regras

```bash
sudo cp rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo ./scripts/validar-e-reiniciar.sh
```

## 5. Teste de fumaça

No Windows:

```powershell
net user naoexiste /domain   # gera ruído de descoberta, confirma Sysmon chegando
```

No Ubuntu:

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep --line-buffered SERVER01
```
