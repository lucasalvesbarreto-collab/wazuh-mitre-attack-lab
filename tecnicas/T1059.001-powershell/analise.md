# Análise: T1059.001 Command and Scripting Interpreter: PowerShell

## Objetivo

Detectar uso malicioso do PowerShell para execução de código, ofuscação e download de payloads
(tática de **Execução**). O PowerShell é nativo, confiável e interage com o sistema sem deixar
arquivos em disco, o que o torna a ferramenta mais comum em ataques a ambientes Windows.

## Mapeamento MITRE ATT&CK

| Técnica | Tática | Regras customizadas |
|---|---|---|
| T1059.001 PowerShell | Execution | 100130 a 100135 |

Técnicas relacionadas, detectadas indiretamente: T1027 (ofuscação, via `-EncodedCommand`),
T1105 (transferência de ferramenta, via download) e T1620 (carga reflexiva, via IEX).

## Duas camadas de detecção

| Camada | Fonte | Vê | Não vê |
|---|---|---|---|
| Processo | Sysmon evento 1 | A linha de comando de cada **processo novo** (flags, Base64, URL) | Comandos digitados dentro de uma sessão PowerShell já aberta |
| Conteúdo | PowerShell/Operational 4104 | O texto do script **já desofuscado**, mesmo dentro de sessão aberta | Nada, se o ScriptBlock Logging estiver desligado |

## Regras

| ID | Nível | Pai | Camada | Lógica |
|---|---|---|---|---|
| 100130 | 12 | 92057, 92027 | Sysmon | `-EncodedCommand` e **todas** as abreviações (`-e`, `-ec`, `-enc`, `-enco`...) com payload Base64 |
| 100131 | 10 | 92027 | Sysmon | `-ExecutionPolicy Bypass` (ou `-exec bypass`) |
| 100132 | 12 | 91837 | 4104 | `IEX` / `Invoke-Expression` no `scriptBlockText` |
| 100133 | 14 | sysmon_event1 | Sysmon | `Net.WebClient`, `DownloadString`, `DownloadFile`, `iwr`... na linha de comando |
| 100134 | 14 | 100130, 100135 | Sysmon | Base64 **e** janela oculta (`-w hidden`): assinatura clássica de stager de C2 |
| 100135 | 12 | sysmon_event1 | Sysmon | Base64 em PowerShell iniciado por processo que **não é PowerShell** (`cmd.exe`, Office, tarefa agendada) |

## Resultados dos testes (07/11/2026)

| # | Teste | Esperado | Resultado |
|---|---|---|---|
| A | `-NoProfile -EncodedCommand <b64>` | 100130 | ✅ 100130 |
| A2 | `-nop -w hidden -enc <b64>` | 100134 | ✅ 100134 |
| A3 | `-ec <b64>` | 100130 | ✅ 100130 |
| B | `Invoke-Expression '...'` | 100132 | ✅ 100132 |
| C | `powershell.exe -Command "(New-Object Net.WebClient).DownloadString(...)"` | 100133 | ✅ 100133 |
| D | `-NoProfile -ExecutionPolicy Bypass` | 100131 | ✅ 100131 |
| A4 | `cmd.exe /c "powershell.exe -nop -enc <b64>"` | experimento | ✅ **100135**. Antes de a regra existir: **nenhum alerta** (ponto cego) |
| A4b | `cmd.exe /c "powershell.exe -nop -w hidden -enc <b64>"` | 100134 | ✅ 100134 |

Os testes B, C e D foram validados na primeira rodada; A, A2 e A3 só passaram depois de
quatro correções, e o A4 revelou um ponto cego que gerou a regra 100135. Tudo descrito abaixo.

## O que deu errado antes de funcionar (e por quê)

Esta seção é a mais valiosa do documento: cada item é uma armadilha real de engenharia de detecção.

### 1. A regra padrão 92057 não reconhece `-enc`

A regex da 92057 (`0800-sysmon_id_1.xml`) aceita uma lista fixa de nomes:

```
-\b(encodedcommand|e|ea|ec|encodeda|encode|en|enco)\b
```

A forma **`-enc`, a mais usada em ataques reais, não está na lista.** Uma regra filha da 92057
herda esse ponto cego. Solução: a 100130 também é filha da **92027** ("PowerShell abriu
PowerShell"), que casa com `-enc`, e usa regex própria para os prefixos.

### 2. Regras irmãs competem, e a primeira carregada vence

A primeira tentativa foi tornar a 100130 independente (`if_group sysmon_event1`). Não funcionou:
as regras padrão carregam **antes** do `local_rules.xml`, casam primeiro e a regra local nunca
é avaliada. Já regras com `if_sid` só são avaliadas depois que o pai casou, e por isso funcionam.

A versão antiga da 100134 tinha o problema inverso: uma regex ampla (`-nop` casava com
`-NoProfile`) fazia com que ela roubasse o alerta da 100130. Como filha da 100130, as duas
deixaram de competir.

### 3. O valor do campo chega escapado

Com `-enc` e payload, o `commandLine` guardado pelo Wazuh é:

```
\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -nop -w hidden -enc VwByAGkA...
```

As barras invertidas fazem parte do valor. Uma regex que tentava casar `powershell.exe"? ` falhou
nos dados reais embora passasse no teste local, que usava a linha "limpa". A regex final
ignora o caminho do executável (`(powershell|pwsh).*?`).

**Regra de ouro:** testar a regex sempre contra o valor **como está no alerta**, nunca contra o
comando como foi digitado.

### 4. O teste rodou sem payload

Os três testes seguintes também não dispararam a 100130 porque a variável `$b64` não existia
na sessão: o PowerShell expande variável não definida para texto vazio, **sem avisar**, e a linha
de comando ficou `... -enc` sem nada depois. A regex exige Base64 (≥ 20 caracteres), então o
comportamento estava correto. Os testes passaram a verificar `$b64.Length` antes de executar.

### 5. O 4104 não aparecia

Só `EnableScriptBlockLogging=1` gera 4105/4106. O 4104 (que contém o texto) só aparece com
`EnableScriptBlockInvocationLogging=1` também. Diagnóstico feito de trás para frente: primeiro
confirmar o evento na origem (`Get-WinEvent` no Windows), depois a coleta, depois a regra.

### 6. O Teste C original era invisível ao Sysmon

`(New-Object Net.WebClient).DownloadString(...)` digitado numa sessão aberta não cria processo
novo, então não existe evento Sysmon 1. Só o 4104 enxerga esse caso. O teste correto invoca um
`powershell.exe` filho (`-Command "..."`).

### 7. Ponto cego do processo pai (teste A4)

`cmd.exe /c "powershell.exe -nop -enc <b64>"` **não gerou nenhum alerta** com as regras
100130-100135: as regras padrão 92057 e 92027 exigem PowerShell como processo pai, e aqui o pai é o
`cmd.exe`. O Sysmon registrou o processo; o Wazuh não alertou. É o caminho típico de macro do
Office, tarefa agendada e dropper. A **100135** cobre esse caso com `if_group sysmon_event1`, que
funciona porque nenhuma regra padrão casa antes nesse evento.

### 8. Um comando, dois processos, dois alertas

Na primeira versão, a 100135 gerou **dois alertas** para um único comando. Conferindo `image` e
`parentImage` nos alertas: um era do `cmd.exe` (criado pelo PowerShell do teste, carregando o
Base64 na própria linha de comando) e o outro do `powershell.exe` real (criado pelo `cmd.exe`).
Solução: filtrar `win.eventdata.image` para `powershell.exe`/`pwsh.exe`, de modo que só o processo
que de fato executa o payload alerte. **Lição:** `cmd /c "..."` duplica a linha de comando em dois
eventos; regra de linha de comando deve dizer também *qual processo* quer.

## Ruído e falsos positivos

| Origem | Causa | Tratamento |
|---|---|---|
| Regra 92213 (nível 15) | Toda execução do PowerShell cria `__PSScriptPolicyTest_*.ps1` em `%TEMP%`; o Sysmon (evento 11) classifica como "arquivo dropado em pasta de malware" | Falso positivo conhecido, **independe das regras deste projeto**. Candidata a ajuste (regra de nível 0 filtrando por `targetFilename`) |
| Scripts de TI | Uso legítimo de `-ExecutionPolicy Bypass` | Verificar `parentImage`; allowlist por script ou usuário; preferir assinar scripts |
| Automação | Módulos que usam `IEX` legitimamente | Ler o `scriptBlockText` completo |
| 92027 (nível 4) | Dispara em todo PowerShell abrindo PowerShell | Regra padrão, baixa severidade |

## Limitações

- **Cobertura de pai:** 100130 e 100131 dependem de 92057/92027 (PowerShell como pai). Base64 vindo
  de outros pais é coberto pela 100135, mas `-ExecutionPolicy Bypass` vindo de `cmd.exe` **não**
  tem cobertura equivalente.
- **Irmãs sob o mesmo pai:** 100130 e 100131 são filhas da 92027; um comando com Base64 **e**
  `-ExecutionPolicy Bypass` gera só o alerta da regra carregada primeiro (100130).
- **100133** só vê download em processo novo; em sessão aberta, depende do 4104.
- **100132** exige ScriptBlock Logging habilitado; um atacante com privilégio pode desligá-lo.
- A regex de prefixos (`-en[a-z]{0,12}`) também casaria um argumento qualquer iniciado por
  `-en` seguido de 20+ caracteres Base64, o que é raro.
- Ofuscação por concatenação de strings escapa da camada de processo, mas é capturada pelo 4104.
- PowerShell 7 (`pwsh.exe`) está na regex, mas as regras padrão pai foram escritas para
  `powershell.exe`.

## Melhorias futuras

- Cobrir também `-ExecutionPolicy Bypass` e download vindos de pais que não são PowerShell
  (o Base64 já é coberto pela 100135).
- Correlação PowerShell → criação de conta (T1059.001 → T1136.002) e → grupo privilegiado (T1098).
- Correlação download (100133) seguido de IEX (100132).
- Regra de nível 0 para silenciar o falso positivo 92213 do `__PSScriptPolicyTest`.
- Converter as regras para Sigma.

## Lições aprendidas

1. **Teste a regex contra o dado real**, não contra o que você digitou: campos do eventchannel
   chegam escapados.
2. **`if_sid` herda os pontos cegos do pai.** Descobrir que a 92057 não cobre `-enc` só foi
   possível comparando a regex padrão com a linha de comando real.
3. **Regras irmãs não "somam": a primeira carregada vence.** Regra local com `if_group` perde
   para regra padrão que casa antes; regra filha só existe se o pai casar.
4. **Valide a entrada do teste** (`$b64.Length`) antes de culpar a regra.
5. **Depure de trás para frente:** o evento existe na origem? Foi coletado? Casou com o pai?
   Casou com a filha?
6. **Falha de teste é informação:** as quatro falhas viraram limitações e correções documentadas.

## Evidências

Prints do dashboard em `evidencias/`:

- `T1059.001-01-base64-100130-100135.png`: cadeia Base64: 100130, 100134 e 100130 (testes A, A2 e A3)
- `T1059.001-03-bypass-100131.png`: teste D, `-ExecutionPolicy Bypass` (100131)
- `T1059.001-04-iex-100132.png`: teste B, `Invoke-Expression` no ScriptBlock 4104 (100132)
- `T1059.001-05-download-100133.png`: teste C, download via `Net.WebClient` (100133)
- `T1059.001-06-ruido-92213.png`: alerta 92213 expandido, com `__PSScriptPolicyTest` em `targetFilename`
- `T1059.001-07-cmd-100135.png`: teste A4, alerta com `cmd.exe` como processo pai do `powershell.exe` (100135)
