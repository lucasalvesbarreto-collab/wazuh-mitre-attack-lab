# Análise: T1098 Account Manipulation

## Objetivo

Detectar a manipulação de grupos privilegiados no Windows — especialmente a adição de contas
a **Administradores local** (Builtin S-1-5-32-544) e a **Domain Admins** — e correlacionar
essa ação com a criação de conta que a precedeu, identificando a cadeia completa de persistência.

A técnica T1098 é frequentemente usada após uma intrusão inicial (T1078, T1110) para garantir
que o atacante mantenha acesso privilegiado mesmo que a credencial original seja removida.

## Mapeamento MITRE ATT&CK

| Técnica | Tática | Regra customizada |
|---|---|---|
| T1098 Account Manipulation | Persistence, Privilege Escalation | 100122, 100123, 100125 |
| T1136.002 + T1098 (cadeia) | Persistence | 100124 (local Admins), 100126 (Domain Admins) |

**Nota:** as regras padrão do Wazuh para o evento 4732 mapeiam para T1098 de forma genérica,
sem distinguir o grupo-alvo. As regras customizadas filtram pelo SID do grupo
(S-1-5-32-544 para Administradores local) e adicionam a correlação temporal com a criação
de conta, o que é essencial para detectar a cadeia completa de persistência.

## Regras

| ID | Nível | Camada | Lógica |
|---|---|---|---|
| 100122 | 12 | SO (evento 4732) | Adição ao grupo Administradores local (SID S-1-5-32-544), filho da regra padrão 60154 |
| 100123 | 10 | Processo (Sysmon evt 1) | `net localgroup administradores/administrators /add` na linha de comando |
| 100124 | 14 | Correlação | 100122 ocorrendo ≤ 10 min após 100120 (criação de conta), mesmo `subjectUserName` |
| 100125 | 14 | SO (evento 4728) | Adição ao grupo Domain Admins (evento global), filho da regra padrão 60159 |
| 100126 | 15 | Correlação | 100125 ocorrendo ≤ 10 min após 100120 (criação de conta), mesmo `subjectUserName` |

Arquivo da regra: `regra.xml`.

### Por que SID em vez de nome de grupo?

O Windows instala com o nome "Administrators" em inglês ou "Administradores" em português.
O SID S-1-5-32-544, ao contrário, é fixo e universal. Filtrar por SID evita a necessidade
de manter variantes de idioma na regex e garante que a regra funcione em qualquer instalação.

### Estrutura da correlação

```
100120 (conta criada)
    └─ dentro de 10 min, mesmo subjectUserName
           ├─ 100124 (promoção a Admins local) ← dispara quando 100122 ocorre
           └─ 100126 (promoção a Domain Admins) ← dispara quando 100125 ocorre
```

O alerta correlacionado **substitui** o alerta filho (100122 ou 100125) para aquele evento,
evitando duplicação no dashboard.

## Resultados dos testes

Horários exibidos no dashboard (fuso local, UTC-3). O arquivo `alerts.json` usa UTC.

| # | Teste | Esperado | Resultado observado |
|---|---|---|---|
| 1 | `net user /add` + `net localgroup Admins /add` | 100120, 100121, 100122, 100123, **100124** | Todos dispararam. 100124 (nível 14) confirmou a cadeia dentro de 10 min |
| 2 | `net user /add` + `Add-ADGroupMember Domain Admins` | 100120, 100121, **100125**, **100126** | Todos dispararam. 100126 (nível 15) confirmou a cadeia. 100123 não disparou (sem `net localgroup`) |
| 3 | Criação → aguardar 11 min → promover a Domain Admins | 100120, 100121, 100125; **100126 NÃO** | 100126 não disparou; somente 100125 (nível 14) ao promover. Janela de 10 min funcionou corretamente |
| 4 | Promover conta preexistente (sem criação recente) | 100122 ou 100125; correlações NÃO disparam | Somente 100122 ou 100125; sem 100124 nem 100126. Nenhum falso positivo de correlação |

### Comportamento observado em DCs

Em um Domain Controller, `Add-LocalGroupMember` e `Get-LocalGroup` **não funcionam** para
grupos Builtin (Administradores, Operadores de Backup, etc.) porque o DC não tem SAM database
local. O método funcional é:

- `net localgroup Administradores <conta> /add` → gera evento 4732 + Sysmon evt 1
- `Add-ADGroupMember -Identity "<SID-domínio>-512" -Members <conta>` → gera evento 4728 (sem Sysmon para APIs PowerShell)

A regra 100123 (Sysmon) cobre apenas o primeiro método. O segundo não gera linha de comando
visível pelo Sysmon, mas é coberto pela 100125 (via evento 4728).

### O alerta 100124 disparou duas vezes no Teste 1

Durante o ciclo de testes, a regra 100124 disparou em dois momentos distintos porque foram
executados dois ciclos de criação+promoção dentro da janela de 10 minutos. Cada ciclo de
promoção (100122) encontrou uma criação de conta (100120) recente com o mesmo `subjectUserName`
e gerou um alerta separado. Isso é comportamento esperado e desejado — não é duplicação.

## Ruído e falsos positivos

| Origem | Causa | Tratamento |
|---|---|---|
| Provisionamento de contas de serviço | Administradores adicionam contas a grupos privilegiados como parte de implantação | Confirmar com o chamado; allowlist de administradores autorizados em `subjectUserName` (ciente de que cria ponto cego se comprometidos) |
| Onboarding de helpdesk | Nova conta adicionada a grupo privilegiado no processo de integração | Correlacionar com o chamado de onboarding e o horário comercial |
| Scripts de automação de AD | Ferramentas de provisionamento que criam e adicionam contas em sequência | Identificar o processo pai no alerta Sysmon; avaliar allowlist por `parentImage` |
| Contas de administrador legítimas adicionadas a Domain Admins | Expansão planejada do time de AD | Qualquer adição a Domain Admins merece confirmação — nível 14 é intencional |

## Limitações

- **100123** só detecta `net localgroup` via linha de comando. Criação via `Add-LocalGroupMember`,
  APIs WMI/COM ou ferramentas de terceiros não gera linha de comando visível pelo Sysmon.
- A **correlação 100124/100126** depende que a criação de conta (100120) esteja dentro da janela
  de 10 minutos. Um atacante que espere mais de 10 minutos entre criar e promover a conta
  não é correlacionado — cada alerta (100122/100125) dispara individualmente.
- A correlação usa `subjectUserName` (quem executou a ação), não a conta criada. Se o atacante
  usar contas diferentes para criar e para promover, a correlação não dispara.
- **Domain Admins (100125/100126)** só gera evento 4728 no próprio DC. Membros de grupos
  Domain Admins adicionados a partir de outra máquina também chegam como evento 4728 no DC,
  portanto a detecção funciona corretamente.
- O Sysmon não vê a linha de comando de `Add-ADGroupMember` (cmdlet PowerShell que chama a API
  do AD diretamente, sem criar processo filho `net.exe`). A detecção fica pela camada de SO
  (evento 4728).

## Melhorias futuras

- **Correlação completa da cadeia T1110 → T1136.002 → T1098:** elevar a severidade se a conta
  que criou e promoveu a nova conta for a mesma que sofreu brute force (alertas 100112/100113).
- **Detecção de uso da conta backdoor:** alertar quando a conta recém-criada e promovida
  fazer logon (evento 4624) — confirma que o atacante está usando o acesso.
- **Cobertura de `Add-LocalGroupMember`:** habilitar o log de script do PowerShell (evento 4104)
  e criar regra filha baseada no texto do script, complementando o Sysmon.
- **Alerta fora do horário comercial:** elevar severidade se a promoção a Domain Admins ocorrer
  à noite ou no fim de semana.
- Converter para o formato Sigma para portabilidade entre SIEMs.

## Lições aprendidas

1. **DCs têm comportamento diferente de workstations e servidores membros.** `Add-LocalGroupMember`
   não funciona para grupos Builtin em DCs. Descobrir isso durante os testes levou à correção
   do método de simulação — e documentar essa diferença é parte do valor do lab.

2. **Filtrar por SID elimina a dependência de idioma.** A tentativa inicial de filtrar pelo nome
   "Administradores" teria falhado em instalações em inglês. O SID S-1-5-32-544 é universal.

3. **A regra pai correta importa.** O evento 4732 cai na regra padrão 60154 (não 60109).
   Confirmar o ID da regra pai observando o dashboard antes de escrever a regra filha
   evitou um erro que poderia fazer a 100122 nunca disparar.

4. **Correlação temporal é sensível à ordem dos eventos.** A janela de `timeframe` na regra
   100124/100126 conta do `if_matched_sid` (criação) até o `if_sid` (promoção). Se os logs
   chegarem fora de ordem, a correlação pode falhar — importante em ambientes com latência
   de forwarding.

5. **Dois ciclos de teste dentro da janela geram dois alertas de correlação.** Isso é correto
   (cada ciclo é uma ameaça independente), mas pode surpreender o analista. Entre cenários,
   aguardar a janela de 10 minutos expirar.

## Evidências

Prints do dashboard em `evidencias/`:

- `T1098-00-criacao-svc-antiga.png`: criação da conta antiga usada no teste negativo
- `T1098-01-visao-geral.png`: visão geral dos testes
- `T1098-02-admins-local.png`: 100122 e 100123, promoção a Administradores local
- `T1098-03-domain-admins-sem-correlacao-13min.png`: 100125 sem 100126, janela de 10 minutos expirada (13 min)
- `T1098-04-cadeia-completa.png`: cadeia completa: 100120 → 100124 e 100120 → 100126
- `T1098-05-100124-detalhe.png`: alerta 100124 expandido
- `T1098-06-100126-detalhe.png`: alerta 100126 expandido
