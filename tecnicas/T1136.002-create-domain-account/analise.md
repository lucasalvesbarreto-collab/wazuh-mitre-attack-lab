# Análise: T1136.002 Create Account: Domain Account

## Objetivo

Detectar a criação de **contas de domínio** no Active Directory, uma técnica de **persistência**:
o atacante cria uma conta para manter acesso mesmo que a credencial original seja trocada
ou bloqueada. A detecção usa duas camadas independentes, cada uma cobrindo o ponto cego da outra.

## Por que T1136.002 e não T1136.001?

`SERVER01` opera como Domain Controller primário (DomainRole=5). Toda conta criada nele entra
diretamente no Active Directory — não existe banco de contas locais (SAM local) em DCs.
A técnica **T1136.001 (Local Account)** se aplica a workstations e servidores membros.
Em um DC, a criação de conta sempre é **T1136.002 (Domain Account)**.

Essa distinção foi identificada durante os testes ao verificar `DomainRole=5` no PowerShell,
e corrigida nos documentos e nas regras com `sed`.

## Mapeamento MITRE ATT&CK

| Técnica | Tática | Regra customizada |
|---|---|---|
| T1136.002 Create Account: Domain Account | Persistence | 100120 e 100121 |

**Nota:** as regras padrão do Wazuh para esses eventos (60109 "User account enabled or created"
e 60110 "User account changed") mapeiam para **T1098 (Account Manipulation)**.
As regras customizadas corrigem o mapeamento para T1136.002 e acrescentam contexto
(conta criada e quem a criou na description do alerta).

## Regras

| ID | Nível | Camada | Lógica |
|---|---|---|---|
| 100120 | 10 | Sistema operacional | Evento **4720** (conta criada), filho da regra 60109. O filtro `^4720$` exclui os demais eventos da 60109 |
| 100121 | 10 | Processo | Sysmon evento 1 com `net user ... /add` ou `net1 user ... /add` na linha de comando (regex pcre2, case-insensitive) |

Arquivo da regra: `regra.xml`. A description de cada alerta traz a conta criada e quem a
criou (`$(campo)`), poupando o analista de abrir o JSON.

### Cobertura por camada

| Camada | Detecta | Ponto cego |
|---|---|---|
| Evento 4720 (100120) | Qualquer criação de conta, por qualquer método | Não informa qual ferramenta foi usada |
| Sysmon evento 1 (100121) | A linha de comando `net user /add` explicitamente | Não vê criação via `New-ADUser`, APIs COM/WMI ou ferramentas de terceiros |

A **diferença entre as camadas é informativa:** 100120 sem 100121 indica criação por API
ou PowerShell, e merece investigação mais atenta do processo pai.

## Resultados dos testes

Horários do dashboard (fuso local, UTC-3). O `alerts.json` usa UTC.

| # | Teste | Esperado | Resultado observado |
|---|---|---|---|
| 1 | `net user svc_backup /add /domain` | 100120 e 100121 disparam | Ambas dispararam. A 100120 mostrou "conta de domínio criada - svc_backup por servidor" |
| 2 | Troca de senha da conta existente (`net user svc_backup <nova_senha>`) | Nenhuma das duas dispara | Não dispararam. Apenas as regras padrão 60110 e ruído do Sysmon |
| 3 | `New-ADUser svc_update` (cmdlet PowerShell) | Só a 100120 dispara | Só a 100120 disparou. Nenhuma 100121 — o `net.exe` não foi invocado |

O Teste 3 comprova a limitação da detecção por linha de comando: a criação por cmdlet não
passa pelo `net.exe`, e apenas a camada de SO (evento 4720) a enxerga.

## Comportamento observado

- Ao criar uma conta no AD, o Windows registra vários eventos: 4720 (conta criada),
  4722 (conta habilitada), 4738 (conta alterada) e outros. O filtro `^4720$` na regra
  100120 garante que apenas o evento de criação dispara o alerta.
- A regra 60109 gera um alerta próprio para o mesmo evento. A regra filha 100120 **substitui**
  esse alerta para o evento 4720 — o analista vê 100120, não 60109, para criações de conta.
- Um alerta 100120 **sem** 100121 imediatamente antes ou depois indica criação por API/PowerShell.
  Nesse caso, o analista deve verificar no dashboard os eventos Sysmon (evento 1) e PowerShell
  (evento 4104, se habilitado) no mesmo host e janela de tempo.

## Ruído e falsos positivos

| Origem | Causa | Tratamento |
|---|---|---|
| Regras 92033 e 92039 (T1087, nível 3) | O conjunto padrão trata qualquer `net user` como descoberta de contas, sem olhar a flag `/add`. Aparecem também em consultas e trocas de senha | O contexto `/add` da 100121 e o nível 10 separam "listou contas" de "criou conta" |
| Provisionamento de usuários | RH ou helpdesk criando contas normalmente | Confirmar com chamado; allowlist de administradores autorizados em `subjectUserName` (ciente do ponto cego se comprometidos) |
| Scripts de automação de AD | Ferramentas de provisionamento que criam contas em lote | Identificar pelo processo pai no alerta Sysmon; avaliar allowlist por `parentImage` |
| Instaladores de produtos | Alguns produtos criam contas de serviço durante a instalação | Identificar pelo processo pai e horário de instalação |

## Limitações

- A **100121** só cobre `net user` e `net1 user`. Ferramentas como `dsadd user`, `wmic useraccount`
  ou cmdlets de terceiros não passam por ela.
- **Criação via `New-ADUser`** (PowerShell) não gera linha de comando visível pelo Sysmon —
  a 100121 não dispara, mas a 100120 sim.
- O nome da conta não é avaliado: um nome que imite conta de serviço (`svc_*`) não gera
  severidade maior automaticamente.
- Depende da política de auditoria "User Account Management" ativa no alvo; sem ela,
  o evento 4720 não é gerado e a 100120 fica sem dados.
- Contas criadas **em outro servidor ou workstation** para acessar o domínio não geram
  evento 4720 no DC (o evento ocorreria na máquina local, que não é um DC e usaria T1136.001).

## Melhorias futuras

- **Correlação com T1098 já implementada** (regras 100124 e 100126): quando a conta recém-criada
  for adicionada a grupos privilegiados em até 10 minutos, um alerta de nível 14 ou 15 é gerado.
- **Correlação com acesso:** alertar quando a conta criada fizer logon (evento 4624) logo após
  a criação — confirma que o atacante está usando a backdoor.
- **Cadeia com T1110:** elevar a severidade se a conta que criou a nova conta for a mesma
  do alerta 100112 ou 100113 (acesso por força bruta seguido de persistência).
- Alertar por criação fora do horário comercial ou nos fins de semana.
- Converter as regras para o formato Sigma para portabilidade entre SIEMs.

## Lições aprendidas

1. **Conhecer o papel do servidor antes de classificar a técnica.** A identificação de que
   SERVER01 era um DC (DomainRole=5) mudou a técnica de T1136.001 para T1136.002. O MITRE
   ATT&CK distingue os dois subtipos justamente por isso: o impacto e a persistência são
   maiores em contas de domínio.

2. **A regra pai determina a cobertura.** A regra 60109 cobre evento 4720 e outros eventos de
   conta. O filtro `^4720$` na 100120 garante que só a criação dispara — sem ele, a regra
   dispararia para habilitação, renomeação e outras alterações.

3. **Duas camadas se complementam.** O analista que vê 100120 sem 100121 já sabe que a criação
   não foi por linha de comando — essa informação direciona a investigação sem precisar de
   uma regra adicional.

4. **Nomenclatura de conta é um sinal débil mas informativo.** Nomes como `svc_backup`,
   `svc_update` ou `helpdesk01` são frequentemente usados por atacantes para se camuflar.
   Registrar o nome no alerta (via `$(campo)` na description) acelera a triagem.

## Evidências

Guardadas em `evidencias/`:

- [ ] Print do dashboard com 100120 e 100121 na criação via `net user /add`
- [ ] Print do teste negativo (troca de senha sem 100120 nem 100121)
- [ ] Print do teste via `New-ADUser` (100120 sem 100121)
- [ ] `alerta-100120.json` e `alerta-100121.json`
