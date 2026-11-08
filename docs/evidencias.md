# Índice de evidências

Prints do dashboard e JSONs dos alertas, organizados por técnica. Os prints vão em
`tecnicas/<técnica>/evidencias/`; os JSONs são gerados por `scripts/exportar-evidencias.sh`.

> Exporte os JSONs **antes da meia-noite UTC (21:00 em Brasília)**: o `alerts.json` é rotacionado
> e o script só lê o arquivo do dia.

## Prints existentes (rodada de 07/11/2026) e destino sugerido

| Print atual | Mover para | Renomear para |
|---|---|---|
| 100110 8 falhas na mesma conta.png | T1110-brute-force | T1110-01-100110-8-falhas.png |
| teste 2 negativo, apenas 3 falhas.png | T1110-brute-force | T1110-02-negativo-3-falhas.png |
| falhas seguidas de logon correto.png | T1110-brute-force | T1110-03-falhas-seguidas-de-logon.png |
| Teste de spray.png | T1110-brute-force | T1110-04-spray-100111.png |
| spray + logon 100112.png | T1110-brute-force | T1110-05-spray-logon-100112-sobreposicao.png |
| t1136.002.png | T1136.002-create-domain-account | T1136.002-01-net-user-add.png |
| troca de senha 60110.png | T1136.002-create-domain-account | T1136.002-02-negativo-troca-de-senha.png |
| so 100120 sem 100121.png | T1136.002-create-domain-account | T1136.002-03-new-aduser-so-100120.png |
| Criação conta antiga.png | T1098-account-manipulation | T1098-00-criacao-svc-antiga.png |
| T1098.png | T1098-account-manipulation | T1098-01-visao-geral.png |
| 100122 + 100123.png | T1098-account-manipulation | T1098-02-admins-local.png |
| 100125 + 100126.png | T1098-account-manipulation | T1098-03-domain-admins-sem-correlacao-13min.png |
| Teste D bypass 100131.png | T1059.001-powershell | T1059.001-03-bypass-100131.png |
| Teste IEX 100132.png | T1059.001-powershell | T1059.001-04-iex-100132.png |
| Teste C download 100133.png | T1059.001-powershell | T1059.001-05-download-100133.png |

## Prints que faltam

- [ ] **T1098:** a lista com a cadeia completa (100120 → 100124 e 100120 → 100126, de 15:16 locais)
      e as linhas 100124 e 100126 **expandidas** (`T1098-04-cadeia-completa.png`, `...-100126-detalhe.png`)
- [ ] **T1059.001:** a lista com 100130 (21:32:38), 100134 (21:32:58) e 100130 (21:33:19)
      (`T1059.001-01-base64-100130-100135.png`)
- [ ] **T1059.001:** um 92213 expandido com `targetFilename` (`T1059.001-06-ruido-92213.png`)
- [ ] **T1059.001:** um alerta **100135 expandido** (`parentImage` = cmd.exe, `image` = powershell.exe) e o A4b (100134) (`T1059.001-07-cmd-100135.png`)

## JSONs exportados

| Técnica | Regras com JSON | Sem JSON |
|---|---|---|
| T1110 | 100110, 100111, 100112 | 100113 |
| T1136.002 | 100120, 100121 | — |
| T1098 | 100122 a 100126 | — |
| T1059.001 | 100130 a 100134 | 100135 (exportar após o retest) |

Antes do commit, abra um ou dois JSONs: eles contêm IP, nome do host e usuários do lab.
