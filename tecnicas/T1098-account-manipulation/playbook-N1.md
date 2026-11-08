# Playbook N1: manipulação de grupos privilegiados (T1098)

Aplica-se aos alertas **100122** (adição ao grupo Administradores local, evento 4732),
**100123** (`net localgroup /add` executado, Sysmon), **100124** (correlação: conta criada
e promovida a Admins local em 10 min), **100125** (adição ao Domain Admins, evento 4728)
e **100126** (correlação: conta criada e promovida a Domain Admins em 10 min).

| Alerta | Significado | Severidade |
|---|---|---|
| 100122 | Uma conta foi adicionada ao grupo Administradores local | Alta (nível 12) |
| 100123 | O comando `net localgroup /add` foi executado | Média (nível 10) |
| 100124 | Conta criada e promovida a Admins local em ≤ 10 min pelo mesmo operador | **Crítica** (nível 14) |
| 100125 | Uma conta foi adicionada ao grupo Domain Admins | **Crítica** (nível 14) |
| 100126 | Conta criada e promovida a Domain Admins em ≤ 10 min pelo mesmo operador | **Máxima** (nível 15) |

> **Qualquer alerta 100125 ou 100126 deve ser tratado como incidente até prova em contrário.**
> Domain Admins tem controle total sobre o domínio Active Directory.

## 1. Coletar o contexto

Abra o alerta e anote os seguintes campos:

- `agent.name` — máquina onde a ação ocorreu (em DCs, o agente é o próprio DC)
- `data.win.eventdata.subjectUserName` — **quem** adicionou o membro ao grupo
- `data.win.eventdata.memberSid` — SID da conta promovida (resolva para nome com `Get-ADUser` se necessário)
- `data.win.eventdata.targetSid` — SID do grupo (S-1-5-32-544 = Admins local)
- `data.win.eventdata.commandLine` e `parentImage` (nos alertas Sysmon 100123) — como foi feito
- Hora exata do evento (lembrar que o dashboard exibe UTC-3; `alerts.json` usa UTC)

Para os alertas de correlação (100124, 100126), o alerta trará dois eventos encadeados:
a criação da conta (100120 referenciada em `if_matched_sid`) e a promoção. Coloque os
dois timestamps na linha do tempo.

## 2. Triagem

### 2.1 Foi autorizado?

Verifique:

1. Há chamado aberto de administração de AD para esse horário?
2. A conta que executou a ação (`subjectUserName`) é um administrador de AD esperado?
3. A conta adicionada (`memberSid` → nome) é uma conta de serviço ou usuário conhecido?

### 2.2 Como foi feita a promoção?

| Situação | Ação |
|---|---|
| 100122 e 100123 juntos | `net localgroup /add` em linha de comando — risco elevado (típico de atacantes) |
| Só 100122 | API PowerShell (`Add-LocalGroupMember`) ou ferramenta de terceiro — investigar processo pai |
| 100125 (Domain Admins) | Independente do método, escalar imediatamente para N2 |
| 100124 ou 100126 | Conta criada e promovida em sequência — provável backdoor. Tratar como incidente |

### 2.3 A conta promovida é legítima?

```powershell
# Resolve o SID do membro para o nome da conta
# (executar no DC como admin)
$sid = "<SID-do-memberSid>"
(New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
```

- A conta existia antes do evento, ou foi criada recentemente (alertas 100120/100121 na mesma janela)?
- O nome da conta parece uma conta de serviço legítima, ou imita padrões suspeitos (`svc_update`, `backup01`, `helpdesk`)?

### 2.4 Há contexto de intrusão anterior?

Pesquise no dashboard (Last 24h):

```
agent.name: SERVER01 and rule.id: (100110 or 100111 or 100112 or 100113 or 100120 or 100121)
```

Se houver alertas de brute force (100110–100113) ou criação de conta (100120–100121) antes
da promoção, trate como incidente imediatamente — a cadeia completa T1110 → T1136.002 → T1098
indica comprometimento ativo.

## 3. Decisão

```
                        ┌─ Autorizado e documentado → Fechar como FP, registrar o chamado
Alerta recebido ───────►│
                        ├─ Conta desconhecida OU sem chamado → Tratar como incidente (seção 4)
                        │
                        ├─ 100125 ou 100126 (Domain Admins) → Escalar para N2 imediatamente
                        │
                        └─ Inconclusivo → Escalar para N2 com contexto coletado
```

## 4. Resposta (promoção não autorizada)

### 4.1 Contenção imediata

```powershell
# Remover a conta do grupo Administradores local
net localgroup Administradores <nome_da_conta> /delete

# Remover a conta do grupo Domain Admins (usar SID do domínio)
$domSid = (Get-ADDomain).DomainSID.Value
Remove-ADGroupMember -Identity ($domSid + "-512") -Members <nome_da_conta> -Confirm:$false

# Desabilitar a conta sem apagá-la (preservar evidências)
Disable-ADAccount -Identity <nome_da_conta>

# Encerrar sessões ativas da conta
# Verificar logons ativos
query session /server:SERVER01
# Encerrar a sessão pelo ID
logoff <id_da_sessao> /server:SERVER01
```

> **Não apagar a conta antes de coletar as evidências** (logs de logon, processos iniciados,
> arquivos modificados).

### 4.2 Investigação

1. **Quem criou a conta (`subjectUserName`):** quando essa conta fez logon, de qual IP
   e com qual método? Buscar eventos 4624 recentes para esse usuário.
2. **A conta foi usada?** Buscar evento 4624 com `targetUserName` igual à conta recém-promovida.
3. **Quais ações foram realizadas com a conta privilegiada?** Verificar eventos de logon,
   execução de processos (Sysmon) e acesso a compartilhamentos (evento 5140) nos últimos
   30–60 minutos.
4. **Há outras persistências?** Verificar no mesmo período:
   - Novas tarefas agendadas (evento 4698)
   - Novos serviços (evento 7045 no System log)
   - Chaves de registro de autostart (Sysmon eventos de alteração de registro)
   - Outras contas criadas ou promovidas

### 4.3 Comunicação

- **100122/100123 (Admins local):** notificar o responsável pela máquina e o líder de segurança.
- **100125/100126 (Domain Admins):** notificar o líder de segurança, o responsável pelo AD
  e abrir incidente formal — Domain Admins comprometido pode afetar todo o domínio.
- Escalar para N2 com o resumo: conta promovida, quem promoveu, método, janela de tempo ativa
  e ações de contenção já tomadas.

### 4.4 Registrar

- Exportar os JSONs dos alertas para o incidente:

```bash
# Ubuntu — exportar alertas relevantes
for rid in 100120 100121 100122 100123 100124 100125 100126; do
  sudo grep "\"id\":\"${rid}\"" /var/ossec/logs/alerts/alerts.json \
    | tail -n 1 | python3 -m json.tool > incidente-${rid}.json 2>/dev/null
done
```

- Registrar o incidente com horários, ações de contenção e decisões tomadas.

## 5. Fechamento

Classificar como:

- **Verdadeiro positivo:** conta foi promovida sem autorização ou como parte de ataque confirmado.
- **Falso positivo:** promoção legítima não documentada. Registrar a causa e avaliar allowlist.
- **Inconclusivo:** escalar para N2.

Falsos positivos recorrentes devem ser tratados como melhoria de processo (documentar
contas de serviço que precisam estar em grupos privilegiados), nunca como motivo para
silenciar o alerta permanentemente.

## Referências

- MITRE ATT&CK: [T1098](https://attack.mitre.org/techniques/T1098/), [T1136.002](https://attack.mitre.org/techniques/T1136/002/), [T1078](https://attack.mitre.org/techniques/T1078/)
- Eventos Windows: [4732](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4732), [4728](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4728)
- SID S-1-5-32-544 (Administrators Builtin): [Well-known SIDs](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)
- Regras e análise: `regra.xml`, `analise.md`
- Como reproduzir os cenários: `simulacao.md`
