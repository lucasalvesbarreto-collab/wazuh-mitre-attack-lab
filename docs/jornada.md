# Jornada: diário de bordo do lab

Este documento registra o que **realmente aconteceu** ao construir o lab — incluindo os erros,
as hipóteses que se mostraram erradas e o raciocínio usado para resolver cada problema.
A documentação técnica de cada técnica fica em `tecnicas/`; aqui fica a experiência.

---

## Fase 0 — Reconstrução do ambiente

**Situação:** o lab antigo tinha apenas o Wazuh no Ubuntu. O `wazuh-indexer` não subia:
os certificados em `/etc/wazuh-indexer/certs` estavam ausentes.

**Decisão:** reinstalar o Wazuh do zero em vez de tentar recuperar os certificados.
Num lab, um ambiente limpo e reprodutível vale mais que horas de arqueologia em configuração
quebrada — e o processo de reinstalação vira documentação (`docs/setup-lab.md`).

**Depois:** instalado o agente no Windows Server 2022 (`SERVER01`) e confirmado que os
alertas chegavam ao dashboard antes de escrever qualquer regra.

---

## Fase 1 — T1110 Brute Force

**O que foi feito:** regras para força bruta em uma conta (T1110.001, 100110), password spray
em várias contas (T1110.003, 100111) e sucesso após falhas (100112 / 100113, nível 14).

**Observações:**
- Os eventos 4625 chegaram como regra padrão **60122**, origem `127.0.0.1` nos testes locais.
- O spray via `smbclient` a partir do Ubuntu disparou a 100111 exatamente no **6º usuário
  distinto** — confirmando que o limiar da regra funcionava como projetado.
- Teste negativo: 3 falhas não dispararam a 100110. Logon limpo não disparou a 100112.

**Aprendizado:** definir o limiar (quantas falhas, em quanto tempo) é uma decisão de negócio,
não só técnica: baixo demais gera ruído com usuários que erram a senha; alto demais deixa
passar ataques lentos.

---

## Fase 2 — T1136: a técnica que mudou de número

**O que foi feito:** regra 100120 (evento 4720, conta criada) e 100121 (Sysmon, `net user /add`).

**O problema:** a técnica foi planejada como **T1136.001 (Local Account)**. Ao testar a T1098
logo depois, `Add-LocalGroupMember` retornou "grupo não encontrado" e `Get-LocalGroup` listava
apenas grupos de domínio.

**Investigação:**
```powershell
(Get-WmiObject Win32_ComputerSystem).DomainRole   # retornou 5
```
`DomainRole = 5` significa **Primary Domain Controller**. DCs não têm banco SAM local:
toda conta criada neles é uma conta do Active Directory.

**Correção:** a técnica passou a ser **T1136.002 (Domain Account)** — regras, descriptions
e documentos foram corrigidos. O cenário de teste trocou `New-LocalUser` por `New-ADUser`.

**Aprendizado:** antes de classificar uma técnica, entender o papel do host. O MITRE separa
.001 e .002 justamente porque impacto e investigação são diferentes.

**Resultado bonito:** a diferença entre as camadas virou informação. `New-ADUser` disparou
só a 100120 (sem 100121) — o analista já sabe, só por isso, que a conta não foi criada por
`net.exe` e deve olhar PowerShell.

---

## Fase 3 — T1098: promoção a grupos privilegiados

**O que foi feito:** 100122 (4732 em Administradores, filtrando pelo SID `S-1-5-32-544`),
100123 (`net localgroup /add`), 100125 (4728 em Domain Admins) e duas correlações:
100124 e 100126 — conta **criada e promovida em até 10 minutos** (nível 14 e 15).

**Decisões de projeto:**
- **Filtrar por SID, não por nome do grupo.** O Windows do lab está em português
  ("Administradores"). Um filtro por nome quebraria em outro idioma; o SID é universal.
- **Domain Admins = SID do domínio + `-512`.** Mesmo raciocínio.
- **Correlação com `timeframe="600"`** ligando a promoção à criação (100120): a cadeia
  "criou e já promoveu" é muito mais suspeita que cada evento isolado.

**Testes:** positivo para Admins local e Domain Admins; negativo com 11 minutos de espera
(correlação não dispara) e negativo promovendo conta antiga (só a regra simples dispara).

---

## Fase 4 — T1059.001 PowerShell: a fase mais difícil

### Problema 1: o evento 4104 não chegava

Sequência real de diagnóstico:

1. Testes rodados, nenhum 4104 no Wazuh. **Hipótese:** canal não coletado.
   Adicionado `Microsoft-Windows-PowerShell/Operational` ao `ossec.conf` do agente.
   **Ainda nada.**
2. Verificado na origem, no próprio Windows:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 20
   ```
   Apareciam **4105 e 4106**, mas **nenhum 4104**. Ou seja: o problema não era o Wazuh,
   era o Windows que não gerava o evento.
3. Adicionada a chave `EnableScriptBlockInvocationLogging = 1` (além da
   `EnableScriptBlockLogging = 1` já existente). O 4104 apareceu imediatamente.

**Aprendizado:** depurar o pipeline **de trás para frente** — primeiro confirmar que o evento
existe na origem, depois que é coletado, depois que casa com uma regra. Mexer no SIEM quando
o problema está no endpoint é perder tempo.

### Problema 2: falso positivo no próprio grep

Um `grep 4104` no `alerts.json` encontrou resultados — mas eram o **próprio comando `sudo grep`**
registrado pela regra 5402 (comandos sudo). O SIEM monitora o analista também.

### Problema 3: comandos no terminal errado

`Get-WinEvent` executado no bash do Ubuntu → `command not found`. Detalhe bobo, mas real:
com dois terminais lado a lado, conferir o prompt (`PS C:\>` vs `servidor@servidorubuntu:~$`).

### Problema 4: duas regras não dispararam (e a primeira explicação estava errada)

Após aplicar as regras, 100131, 100132 e 100134 dispararam; **100130 e 100133 não**.

- **100133 (download):** `(New-Object Net.WebClient).DownloadString(...)` digitado numa sessão
  aberta não cria processo novo, então não existe Sysmon evento 1. Esse caso só aparece no 4104.
  Corrigido testando via `powershell.exe -Command "..."`.
- **100130 (Base64):** a regex da 100134 casava `-NoProfile` como `-nop` e roubava o alerta da
  100130 (o Wazuh emite um alerta por evento). A 100134 virou **filha** da 100130 e passou a
  exigir `-w hidden`.

### Problema 5: a rodada de evidências revelou mais quatro falhas

Ao repetir os testes só para tirar prints, a cadeia 100130 → 100134 ainda não funcionava.
A investigação levou quatro tentativas, e cada uma ensinou algo:

1. **A regra padrão 92057 não cobre `-enc`.** A regex dela aceita uma lista fixa
   (`encodedcommand|e|ea|ec|encodeda|encode|en|enco`) e a forma mais usada em ataques reais
   ficou de fora. Descoberto comparando o `commandLine` real com `grep -rn` no ruleset.
2. **Regra local com `if_group` perde para regra padrão.** Eu tinha assumido o contrário.
   Regras irmãs são avaliadas na ordem de carregamento e a primeira que casa vence; o ruleset
   padrão carrega antes do `local_rules.xml`. A solução foi `if_sid` com **lista** de pais
   (`92057,92027`).
3. **O campo chega escapado.** Meu teste local usava a linha "limpa"; no Wazuh o valor é
   `\"C:\\Windows\\...\\powershell.exe\" -enc ...`. A regex falhava nos dados reais.
   Lição: testar regex contra o **valor do alerta**, não contra o que se digitou.
4. **O teste estava sem payload.** A variável `$b64` não existia na sessão; o PowerShell
   expande variável não definida para vazio, sem avisar. A prova estava no `repr` da linha de
   comando, que terminava em `-enc'` sem nada depois. A regra estava certa e o teste, errado.

### Problema 6: o ponto cego do processo pai (teste A4)

`cmd.exe /c "powershell.exe -nop -enc <b64>"` não gerou **nenhum alerta**: as regras padrão pai
(92057/92027) exigem PowerShell como processo pai. Criei a 100135 (`if_group sysmon_event1`), que
funciona aqui porque nenhuma regra padrão casa antes nesse evento. Na primeira versão ela alertou
**duas vezes** por comando. Para entender o motivo, conferi os campos do alerta com um parser:

```python
import json
with open("/var/ossec/logs/alerts/alerts.json", "rb") as f:
    for raw in f:
        try: a = json.loads(raw.decode("utf-8", "replace"), strict=False)
        except json.JSONDecodeError: continue
        if a.get("rule", {}).get("id") in ("100135", "100134"):
            ed = a["data"]["win"]["eventdata"]
            print(a["timestamp"][11:23], a["rule"]["id"], ed.get("image"), "<-", ed.get("parentImage"))
```

Um alerta era do `cmd.exe` (que carrega o Base64 na própria linha de comando) e o outro do
`powershell.exe` real. O filtro `win.eventdata.image` para `powershell.exe`/`pwsh.exe` eliminou a
duplicata. Palpite formulado, **confirmado com dados** e só então corrigido.

### Problemas de operação na coleta de evidências

- **`grep` dizendo "binary file matches":** o `alerts.json` tem bytes que não são UTF-8 (acentos
  do Windows em português); o `grep` trata o arquivo como binário e não imprime a linha. Solução:
  `grep -a`, e parsear JSON com Python tolerante (`decode("utf-8", "replace")`).
- **Rotação de logs à meia-noite UTC:** o `alerts.json` é arquivado à 00:00 UTC (21:00 em
  Brasília). Passado esse horário o script de exportação dizia "sem alerta" para tudo; os alertas
  estavam no arquivo compactado. Exporte as evidências **antes** da meia-noite UTC.
- **Correlação de 10 minutos × tempo de print:** as regras 100124/100126 não dispararam porque
  entre criar a conta e promovê-la passaram 13 a 16 minutos tirando prints. O positivo exigiu
  criar e promover **no mesmo bloco de comandos**.
- **Duas correlações no mesmo evento:** no spray + logon correto, a 100112 venceu a 100113
  porque o brute force anterior ainda estava na janela.
- **Comandos de Windows no terminal do Ubuntu (de novo):** o `net` do Samba e o bash tentando
  ler `1..8 | ForEach-Object`. Conferir o prompt antes de colar.
- **Comando de shell que depende de permissão:** `sudo grep ... *.xml` falha porque o **shell**
  expande o curinga antes do `sudo`. Usar `grep -r --include`.
- **Extrair JSON com regex:** `"commandLine":"[^"]*"` parou na primeira aspa escapada. JSON se
  lê com parser.

**Aprendizado geral:** regra que não dispara é um resultado, não um fracasso. Cada uma das
falhas acima virou ou uma limitação documentada ou uma regra melhor.

---

## Práticas que adotei ao longo do projeto

- **Heredoc com `'EOF'` entre aspas** ao escrever regras pelo terminal. Sem aspas, o bash
  interpreta `$(win.eventdata.user)` da description como substituição de comando.
- **`wazuh-analysisd -t` antes de todo restart.** Um XML quebrado derruba o manager.
- **Observar antes de escrever.** Rodar a simulação sem regra, ver qual regra padrão dispara
  e usar o ID dela como `if_sid` — em vez de adivinhar.
- **Senhas fora do repositório.** Placeholders `<SENHA_DE_LAB>` e `Read-Host -AsSecureString`
  / `read -rs` para não expor nada no histórico do shell.
- **Fuso horário:** o dashboard mostra UTC-3, o `alerts.json` usa UTC. Errar isso faz parecer
  que um alerta "não chegou".
