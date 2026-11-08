# Arquitetura do lab

## Componentes

| Host | Função | Software |
|---|---|---|
| `servidorubuntu` (Ubuntu Server) | SIEM | Wazuh manager, indexer e dashboard (all-in-one) |
| `SERVER01` (Windows Server 2022, `192.168.5.130`) | Alvo monitorado — Primary Domain Controller (DomainRole=5) | Wazuh agent, Sysmon, Active Directory |

Rede **host-only** entre as VMs, sem rota para a internet. O Windows está em português,
o que influenciou decisões como filtrar grupos por SID em vez de nome.

## Fluxo de um evento

```
1. Ação no Windows (ex.: net user svc_backup /add)
        │
        ▼
2. Windows grava o evento no canal
   ├─ Security ................... 4720 (conta criada)
   ├─ Sysmon/Operational ......... 1    (processo net.exe com commandLine)
   └─ PowerShell/Operational ..... 4104 (texto do ScriptBlock)
        │
        ▼
3. Agente Wazuh lê os canais configurados em <localfile> (ossec.conf)
        │  TCP 1514 (criptografado)
        ▼
4. Manager: decoder windows_eventchannel → campos win.system.* / win.eventdata.*
        │
        ▼
5. Árvore de regras: regra padrão (ex.: 60109) → regra filha customizada (ex.: 100120)
   Um evento gera UM alerta: o da regra mais específica que casou.
        │
        ▼
6. Alerta gravado em /var/ossec/logs/alerts/alerts.json e indexado → dashboard
```

## Canais coletados e o que cada um entrega

| Canal | Eventos usados | Campo-chave | Regras |
|---|---|---|---|
| Security | 4625, 4624, 4720, 4728, 4732 | `targetUserName`, `subjectUserName`, `targetSid`, `memberSid` | 100110–100113, 100120, 100122, 100125 |
| Sysmon/Operational | 1 (ProcessCreate) | `commandLine`, `parentImage`, `user` | 100121, 100123, 100130, 100131, 100133, 100134 |
| PowerShell/Operational | 4104 (ScriptBlock) | `scriptBlockText` | 100132 |

## Convenções

- IDs customizados na faixa **100100–100199**, em blocos de 10 por técnica.
- Grupo `attack_lab` em todas as regras, para filtrar no dashboard: `rule.groups: attack_lab`.
- Description sempre começa com o ID da técnica (`T1098: ...`) e inclui os campos relevantes
  via `$(campo)`, para o analista entender o alerta sem abrir o JSON.
