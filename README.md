# Wazuh MITRE ATT&CK Detection Lab

Laboratório de **engenharia de detecção** com Wazuh SIEM: regras customizadas mapeadas ao
MITRE ATT&CK, validadas com simulações controladas contra um Domain Controller Windows,
e documentadas como um time de SOC documentaria — análise técnica e playbook de triagem N1
para cada técnica.

> Projeto de portfólio com foco em Segurança / DevSecOps. Todas as simulações rodaram em
> rede isolada (host-only), sem acesso externo. Nenhuma credencial real está versionada.

## O que este projeto demonstra

- **Escrita de regras Wazuh** (XML, PCRE2, `if_sid`, `if_group`, correlação temporal com `timeframe`)
- **Telemetria Windows**: Security log (4625, 4720, 4728, 4732), Sysmon (evento 1) e
  PowerShell ScriptBlock Logging (4104)
- **Detecção em camadas**: sistema operacional + processo + conteúdo de script, cada uma
  cobrindo o ponto cego da outra
- **Correlação de cadeia de ataque**: brute force → criação de conta → promoção a Domain Admins
- **Método de validação**: casos positivos *e negativos* para cada regra, com resultados
  reais documentados — inclusive quando a regra **não** disparou e por quê
- **Documentação operacional**: playbooks N1 com árvore de decisão, contenção e escalonamento

## Arquitetura

```
┌─────────────────────────────┐        ┌──────────────────────────────────┐
│  Ubuntu Server              │        │  Windows Server 2022 (SERVER01)  │
│  servidorubuntu             │◄───────│  Domain Controller (DomainRole=5)│
│                             │ 1514/  │                                  │
│  Wazuh manager              │ 1515   │  Wazuh agent                     │
│  Wazuh indexer              │        │   ├─ Security log                │
│  Wazuh dashboard            │        │   ├─ Sysmon/Operational          │
│  local_rules.xml (100100+)  │        │   └─ PowerShell/Operational      │
└─────────────────────────────┘        └──────────────────────────────────┘
                 Rede host-only, sem saída para internet
```

Detalhes em [`docs/arquitetura.md`](docs/arquitetura.md).

## Cobertura MITRE ATT&CK

| Técnica | Tática | Regras | Níveis | Status | Docs |
|---|---|---|---|---|---|
| [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force (.001 / .003) | Credential Access | 100110–100113 | 10–14 | ✅ Validada | [pasta](tecnicas/T1110-brute-force/) |
| [T1136.002](https://attack.mitre.org/techniques/T1136/002/) Create Account: Domain Account | Persistence | 100120–100121 | 10 | ✅ Validada | [pasta](tecnicas/T1136.002-create-domain-account/) |
| [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation | Persistence / Priv. Escalation | 100122–100126 | 10–15 | ✅ Validada | [pasta](tecnicas/T1098-account-manipulation/) |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) PowerShell | Execution | 100130–100135 | 10–14 | ✅ Validada | [pasta](tecnicas/T1059.001-powershell/) |

Visão detalhada (regra a regra) em [`docs/cobertura-mitre.md`](docs/cobertura-mitre.md).

### Cadeia de ataque coberta

```
T1110 Brute Force ──► T1136.002 Conta criada ──► T1098 Promovida a Domain Admins
   100110-100113          100120-100121              100125 + correlação 100126 (nível 15)
                                ▲
              T1059.001 PowerShell (execução que pode originar qualquer etapa)
```

## Estrutura do repositório

```
.
├── README.md                  ← você está aqui
├── docs/
│   ├── arquitetura.md         ← componentes, rede, fluxo dos eventos
│   ├── setup-lab.md           ← como reproduzir o ambiente
│   ├── metodologia.md         ← ciclo simular → observar → escrever → validar
│   ├── cobertura-mitre.md     ← matriz regra × técnica × teste
│   ├── evidencias.md          ← índice dos prints de evidência
│   └── jornada.md             ← diário de bordo: problemas reais e como foram resolvidos
├── rules/
│   └── local_rules.xml        ← todas as regras customizadas consolidadas
├── config/
│   ├── agent-localfile.xml    ← canais coletados pelo agente Windows
│   └── habilitar-scriptblock-logging.ps1
├── scripts/
│   ├── validar-e-reiniciar.sh ← valida sintaxe antes de reiniciar o manager
│   ├── exportar-regras.sh     ← copia local_rules.xml do manager para o repo
│   └── exportar-evidencias.sh ← salva o JSON do último alerta de cada regra
└── tecnicas/
    └── <técnica>/
        ├── regra.xml          ← regras da técnica, comentadas linha a linha
        ├── simulacao.md       ← como reproduzir cada cenário de teste
        ├── analise.md         ← resultados, ruído, limitações, lições
        ├── playbook-N1.md     ← triagem e resposta para o analista N1
        └── evidencias/        ← prints do dashboard
```

## Como usar

```bash
# 1. Copiar as regras para o manager
sudo cp rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml

# 2. Validar sintaxe e reiniciar (o script só reinicia se a validação passar)
sudo ./scripts/validar-e-reiniciar.sh

# 3. Reproduzir um cenário (ex.: tecnicas/T1098-account-manipulation/simulacao.md)
#    e consultar no dashboard:  rule.id: (100120 or 100125 or 100126)
```

Pré-requisitos do agente Windows (Sysmon, auditoria e ScriptBlock Logging) em
[`docs/setup-lab.md`](docs/setup-lab.md).

## Principais aprendizados

Os detalhes estão em [`docs/jornada.md`](docs/jornada.md). Os mais importantes:

1. **Conhecer o papel do host muda a técnica.** O alvo era um Domain Controller — não existe
   conta local nele. O que seria T1136.001 virou T1136.002, e `Add-LocalGroupMember` em grupo
   Builtin simplesmente não funciona em DC.
2. **Telemetria que não chega não detecta nada.** O evento 4104 só apareceu depois de três
   ajustes: chave `EnableScriptBlockLogging`, chave `EnableScriptBlockInvocationLogging` e o
   canal `PowerShell/Operational` no `ossec.conf` do agente.
3. **Regras irmãs competem pelo mesmo evento, e a primeira carregada vence.** O Wazuh emite um
   alerta por evento. Uma regex ampla (`-nop` casando com `-NoProfile`) fez a 100134 roubar o
   alerta da 100130, e uma regra local com `if_group` perdeu para a regra padrão que carrega antes.
4. **Sysmon evento 1 vê criação de processo, não chamada de método.** Um `DownloadString`
   dentro de uma sessão PowerShell aberta é invisível para ele — só o ScriptBlock (4104) vê.
5. **Teste negativo vale tanto quanto o positivo.** Toda regra foi testada também no cenário
   em que *não* deveria disparar.
6. **Teste a regex contra o dado real.** O Wazuh guarda o `commandLine` escapado
   (`\"C:\\Windows\\...\\powershell.exe\" -enc ...`); uma regex que passava no teste local falhou no alerta de verdade.
7. **Regras padrão têm pontos cegos.** A 92057 não reconhece `-enc`, a abreviação mais usada em
   ataques. Uma regra filha herda esse ponto cego se não for escrita com cuidado.

## Roadmap

- [x] Corrigir 100130/100134 e revalidar a cadeia Base64 (07/11/2026)
- [x] Cobrir `-enc` vindo de `cmd.exe`/Office (regra 100135, teste A4)
- [ ] Silenciar o falso positivo 92213 (`__PSScriptPolicyTest`)
- [ ] Evitar a sobreposição 100112 × 100113
- [ ] T1053.005 Scheduled Task · T1543.003 Windows Service · T1003 Credential Dumping
- [ ] Correlação PowerShell → criação de conta (T1059.001 → T1136.002)
- [ ] Converter regras para Sigma

## Aviso

Material educacional. Os comandos de simulação reproduzem comportamento de atacantes e devem
ser executados **somente** em ambiente de laboratório isolado e sob sua autorização.

## Autor

**Lucas Alves Barreto** — estudante de Ciência da Computação, em transição para DevSecOps.
