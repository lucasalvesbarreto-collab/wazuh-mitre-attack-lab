# Simulação: T1110 Brute Force

Todas as simulações foram executadas em laboratório isolado contra `SERVER01` (Domain Controller,
IP `192.168.5.130`). Os testes de força bruta contra uma única conta partiram do próprio
`SERVER01` (origem `127.0.0.1`); o spray e o logon final partiram do Ubuntu (`servidorubuntu`).

## Ambiente

| Componente | Detalhe |
|---|---|
| SIEM | Wazuh (manager, indexer e dashboard) no Ubuntu Server, host `servidorubuntu` |
| Alvo | Windows Server 2022 (agente Wazuh `SERVER01`, IP `192.168.5.130`), DC primário do domínio |
| Conta alvo | `usuario.lab`, conta de domínio criada só para o teste |
| Rede | Rede interna/host-only, sem acesso externo |

## Pré-requisitos

Auditoria de logon habilitada no Windows (gera os eventos 4624 e 4625):

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /get /subcategory:"Logon"
```

Regras 100110 a 100113 instaladas no manager (`regra.xml`) e validadas:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t && echo "Sintaxe OK"
sudo systemctl restart wazuh-manager
```

> As senhas são marcadores. Os comandos usam `Read-Host -AsSecureString` (PowerShell) ou
> `read -rs` (bash) para que a senha não fique no histórico do shell.

## Teste 1: várias falhas na mesma conta (positivo da 100110)

No PowerShell do `SERVER01`, oito tentativas com senha errada contra a mesma conta:

```powershell
1..8 | ForEach-Object { net use \\127.0.0.1\IPC$ /user:usuario.lab SenhaErrada$_ 2>$null }
```

**Esperado:** 60122 a cada falha e, na 5ª dentro de 2 minutos, a **100110** (nível 10).
Evidência: `T1110-01-100110-8-falhas.png`.

## Teste 2: poucas falhas (negativo da 100110)

Três falhas apenas, abaixo do limiar de 5:

```powershell
1..3 | ForEach-Object { net use \\127.0.0.1\IPC$ /user:usuario.lab SenhaErrada$_ 2>$null }
```

**Esperado:** só a regra padrão 60122; **nenhuma** 100110.
Evidência: `T1110-02-negativo-3-falhas.png`.

## Teste 3: falhas seguidas de logon correto (positivo da 100112)

Logo após o Teste 1 (dentro de 10 minutos), um logon com a senha correta:

```powershell
net use \\127.0.0.1\IPC$ /user:usuario.lab *      # a senha é pedida no prompt
net use \\127.0.0.1\IPC$ /delete                   # encerra a conexão
```

**Esperado:** logon com sucesso (60106) e, como a 100110 disparou antes para a mesma conta,
a **100112** (nível 14).
Evidência: `T1110-03-falhas-seguidas-de-logon.png`.

## Teste 4: password spraying (positivo da 100111)

No Ubuntu, uma única senha testada contra vários usuários, o padrão do spray:

```bash
read -rs -p "Senha a testar: " SENHA; echo
for u in ana bruno carla diego elisa fabio gabi; do
  smbclient -L //192.168.5.130 -U "${u}%${SENHA}" >/dev/null 2>&1
done
unset SENHA
```

**Esperado:** a **100111** (nível 12) no **6º usuário distinto**.
Evidência: `T1110-04-spray-100111.png`.

## Teste 5: spray seguido de logon correto (sobreposição 100112 × 100113)

Depois do spray, um logon correto a partir do Ubuntu:

```bash
smbclient -L //192.168.5.130 -U usuario.lab        # a senha é pedida no prompt
```

**Esperado pelo desenho:** a 100113 (mesma origem após o spray).
**Resultado real:** a **100112** disparou. A conta `usuario.lab` ainda tinha a 100110 dentro da janela
de 10 minutos, e as duas regras são irmãs com os mesmos pais; vence a primeira avaliada.
Evidência: `T1110-05-spray-logon-100112-sobreposicao.png`.

## Conferência no dashboard

```
rule.id: (60122 or 100110 or 100111 or 100112 or 100113) and agent.name: SERVER01
```

Horários do dashboard em UTC-3; o `alerts.json` usa UTC.
