# Playbook N1: criação de conta de domínio (T1136.002)

Aplica-se aos alertas **100120** (conta de domínio criada, evento 4720) e **100121**
(`net user /add` executado, Sysmon evento 1).

| Alerta | Significado | Severidade |
|---|---|---|
| 100120 | Uma conta de domínio foi criada no Active Directory | Média a alta (nível 10) |
| 100121 | O comando `net user /add` foi executado | Média a alta (nível 10) |
| 100120 **sem** 100121 | Conta criada sem `net user /add` (API, cmdlet PowerShell ou outra ferramenta) | Investigar com mais atenção — não há linha de comando para análise |
| 100120 seguido por 100124 | Conta criada e promovida a Administradores local em ≤ 10 min | **Crítico** — ver Playbook T1098 |
| 100120 seguido por 100126 | Conta criada e promovida a Domain Admins em ≤ 10 min | **Máximo** — ver Playbook T1098 |

> Se os alertas 100124 ou 100126 chegarem junto com 100120, seguir o **Playbook N1 de T1098**,
> que cobre a cadeia completa de persistência.

## 1. Coletar o contexto

Abra o alerta e anote:

- `agent.name` — máquina onde a conta foi criada (em DCs, o agente é o próprio DC)
- `data.win.eventdata.targetUserName` — **conta criada**
- `data.win.eventdata.subjectUserName` — **quem criou**
- `data.win.eventdata.commandLine` e `parentImage` (no alerta Sysmon 100121) — ferramenta usada
- Hora exata do evento (lembrar que o dashboard exibe UTC-3; `alerts.json` usa UTC)

## 2. Triagem

### 2.1 A criação foi autorizada?

Verifique:
1. Há chamado aberto de onboarding, contratação ou criação de conta de serviço para esse horário?
2. `subjectUserName` é um administrador de AD esperado (helpdesk, automação de RH)?
3. O nome da conta (`targetUserName`) segue o padrão da organização?

### 2.2 O nome da conta é suspeito?

Nomes que imitam contas de serviço ou do sistema (`svc_*`, `backup`, `update`, `admin`,
`helpdesk01`) são frequentemente usados por atacantes para se camuflar em listas longas
de contas de serviço. Isso não é prova de ataque, mas merece investigação mais cuidadosa.

### 2.3 Como foi criada?

| Situação | Interpretação |
|---|---|
| 100120 **e** 100121 juntos | Criação via `net user /add` — ferramenta de linha de comando, típica de ataques manuais |
| Só a 100120 | Criação via API ou PowerShell (`New-ADUser`). Procurar eventos do Sysmon (evento 1) e PowerShell (evento 4104, se habilitado) no mesmo host e janela de tempo |

Consulta de apoio no dashboard:

```
agent.name: SERVER01 and data.win.system.eventID: (4720 or 1) and @timestamp:[now-5m TO now]
```

### 2.4 A conta foi promovida logo depois?

Verificar se houve eventos 4732 (adição a Administradores local) ou 4728 (adição a Domain Admins)
nos 10 minutos seguintes à criação:

```
agent.name: SERVER01 and data.win.system.eventID: (4732 or 4728) and @timestamp:[now-15m TO now]
```

Se sim, e se os alertas 100124 ou 100126 estiverem presentes, seguir o Playbook T1098.

### 2.5 Há contexto de intrusão anterior?

```
agent.name: SERVER01 and rule.id: (100110 or 100111 or 100112 or 100113) and @timestamp:[now-24h TO now]
```

Alertas de brute force seguidos de criação de conta indicam que o atacante entrou por força
bruta e está criando persistência (cadeia T1110 → T1136.002). Tratar como incidente.

### 2.6 A conta foi usada?

```
agent.name: SERVER01 and data.win.system.eventID: 4624 and data.win.eventdata.targetUserName: "<conta_criada>"
```

Um logon logo após a criação confirma que a conta backdoor está sendo usada ativamente.

## 3. Decisão

- **Legítimo e autorizado:** registrar a referência do chamado, fechar como falso positivo,
  anotar a causa para ajustar a regra se for recorrente.
- **Não autorizado ou sem explicação:** tratar como persistência de atacante (severidade alta)
  e seguir a seção de resposta.
- **100120 seguido de 100124 ou 100126:** tratar como incidente crítico sem aguardar confirmação
  adicional — seguir imediatamente o Playbook T1098.
- **Inconclusivo:** escalar para N2 com o contexto coletado.

## 4. Resposta (conta não autorizada)

### 4.1 Contenção

```powershell
# Desabilitar a conta sem apagá-la (preservar evidências)
Disable-ADAccount -Identity "<conta_criada>"

# Encerrar sessões ativas (se a conta já tiver feito logon)
query session /server:SERVER01
logoff <id_da_sessao> /server:SERVER01
```

> **Não apagar** a conta antes de coletar evidências. O objeto no AD contém metadados de criação
> e pode ser relevante para a investigação forense.

### 4.2 Investigação

1. **Quem criou (`subjectUserName`):** quando essa conta fez logon, de qual IP e com qual método?
   Buscar eventos 4624 recentes para esse usuário.
2. **Como a conta foi criada:** a linha de comando (100121) ou o processo pai do Sysmon
   revelam a ferramenta usada.
3. **A conta foi promovida?** Buscar eventos 4732 e 4728 com o nome da conta criada no campo
   `memberSid` (resolver o SID).
4. **A conta foi usada?** Buscar eventos 4624 com `targetUserName` igual à conta criada.
5. **Há outras persistências?** Verificar no mesmo período:
   - Novas tarefas agendadas (evento 4698)
   - Novos serviços (evento 7045)
   - Chaves de registro de autostart (eventos Sysmon de registro)
   - Outras contas criadas pelo mesmo `subjectUserName`

### 4.3 Escalar para N2

Incluir no resumo:
- Conta criada, quem criou, ferramenta/método
- Linha do tempo: criação → promoção (se houver) → uso (se houver)
- Ações de contenção já tomadas
- Alertas relacionados (IDs dos eventos e timestamps)

### 4.4 Registrar

```bash
# Ubuntu — exportar alertas para o incidente
for rid in 100120 100121 100124 100126; do
  sudo grep "\"id\":\"${rid}\"" /var/ossec/logs/alerts/alerts.json \
    | tail -n 1 | python3 -m json.tool > incidente-${rid}.json 2>/dev/null
done
```

## 5. Fechamento

Classificar como verdadeiro positivo (ataque real ou simulação autorizada), falso positivo
com a causa registrada, ou inconclusivo escalado. Falsos positivos repetidos devem virar
melhoria de processo (por exemplo, allowlist de administradores autorizados por `subjectUserName`),
e não apenas alertas fechados.

## Referências

- MITRE ATT&CK: [T1136.002](https://attack.mitre.org/techniques/T1136/002/), [T1098](https://attack.mitre.org/techniques/T1098/), [T1078](https://attack.mitre.org/techniques/T1078/)
- Evento Windows: [4720 — A user account was created](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720)
- Regras e análise: `regra.xml`, `analise.md`
- Como reproduzir os cenários: `simulacao.md`
