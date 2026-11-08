# Metodologia

Cada técnica segue o mesmo ciclo. A ideia é nunca escrever uma regra "no escuro".

```
 ┌──────────────┐   ┌───────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
 │ 1. Pesquisar │──►│ 2. Simular    │──►│ 3. Observar  │──►│ 4. Escrever  │──►│ 5. Validar   │
 │ técnica no   │   │ SEM regra     │   │ regra padrão │   │ regra filha  │   │ positivo +   │
 │ MITRE        │   │ customizada   │   │ que disparou │   │ (if_sid)     │   │ negativo     │
 └──────────────┘   └───────────────┘   └──────────────┘   └──────────────┘   └──────┬───────┘
                                                                                      │
                                         ┌──────────────┐                             │
                                         │ 6. Documentar│◄────────────────────────────┘
                                         │ regra, sim., │
                                         │ análise, N1  │
                                         └──────────────┘
```

## 1. Pesquisar

Ler a página da técnica no MITRE ATT&CK: como o atacante executa, quais fontes de dados
detectam (seção *Detection*), quais eventos Windows são gerados.

## 2. Simular sem regra

Executar a técnica no lab com as regras padrão do Wazuh. Isso mostra o que o Wazuh já detecta
sozinho e evita duplicar trabalho.

## 3. Observar a regra pai

No dashboard, identificar qual regra padrão disparou para o evento (ex.: 60109 para o 4720,
92057 para PowerShell com Base64). Esse ID vira o `if_sid` da regra customizada.

**Por que regra filha?** Ela herda o trabalho do decoder e da regra pai, e só precisa
acrescentar o filtro específico. Quando não existe pai adequado, usa-se `if_group`
(ex.: `sysmon_event1`) — mais amplo, e por isso exige regex mais cuidadosa.

## 4. Escrever

- Mapear para a subtécnica correta (`<mitre><id>`)
- Description com contexto (`$(campo)`)
- Nível proporcional à confiança:

| Nível | Uso no projeto |
|---|---|
| 10 | Suspeito, mas com uso legítimo comum (bypass de policy, criação de conta) |
| 12 | Forte indicador (Base64, IEX, adição a Administradores) |
| 14 | Alta confiança ou cadeia correlacionada (download, criou+promoveu) |
| 15 | Cadeia que leva a controle do domínio (criou + Domain Admins) |

## 5. Validar

Para cada regra, pelo menos:
- **Caso positivo:** o comportamento malicioso → a regra dispara
- **Caso negativo:** comportamento parecido e legítimo → a regra **não** dispara

Sempre `sudo /var/ossec/bin/wazuh-analysisd -t` antes de reiniciar o manager.

## 6. Documentar

| Arquivo | Público | Responde |
|---|---|---|
| `regra.xml` | Engenheiro de detecção | O que a regra faz e por quê, linha a linha |
| `simulacao.md` | Quem vai reproduzir | Como gerar cada cenário e onde ver o resultado |
| `analise.md` | Revisor técnico | O que aconteceu nos testes, ruído, limitações, melhorias |
| `playbook-N1.md` | Analista de SOC | O que fazer quando o alerta chegar |
