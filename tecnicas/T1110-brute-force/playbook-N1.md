# Playbook N1: brute force e password spraying (T1110)

Aplica-se aos alertas **100110**, **100111**, **100112** e **100113**.

| Alerta | Significado | Severidade |
|---|---|---|
| 100110 | 5 ou mais falhas de logon para o mesmo usuário em 2 min | Média (nível 10) |
| 100111 | Uma origem falhou contra 6 ou mais usuários distintos em 3 min (spray) | Alta (nível 12) |
| 100112 | Logon **com sucesso** na conta que sofreu brute force | **Crítica** (nível 14) |
| 100113 | Logon com sucesso a partir da origem que fez spray | **Crítica** (nível 14) |

> 100112 e 100113 significam provável comprometimento. Seguir direto para a seção 3.

## 1. Coletar o contexto

Abra o alerta e anote:

- `data.win.eventdata.targetUserName`: conta atacada
- `data.win.eventdata.ipAddress` e `workstationName`: origem das tentativas
- `data.win.eventdata.logonType`: 3 é rede, 10 é RDP, 2 é console
- `data.win.eventdata.status` e `subStatus`: `0xc000006a` é senha errada, `0xc0000064` é usuário inexistente
- Horário exato (dashboard em UTC-3, `alerts.json` em UTC)

## 2. Triagem das falhas (100110 e 100111)

### 2.1 É um erro humano?

- Poucas contas, um IP interno conhecido, uma estação de trabalho: provável usuário digitando a senha errada.
- Conferir se há um logon bem-sucedido do mesmo usuário e da mesma estação logo em seguida.

### 2.2 É um ataque?

| Indício | Interpretação |
|---|---|
| IP externo ou de uma máquina que não costuma autenticar | Suspeito |
| Muitos usuários, uma senha (100111) | Spray, ataque deliberado |
| `subStatus 0xc0000064` em muitas contas | O atacante testa nomes que podem nem existir |
| Falhas em ritmo regular, de um serviço | Conta de serviço com senha desatualizada |

Consulta de apoio:

```
data.win.system.eventID: 4625 and data.win.eventdata.ipAddress: "<IP>" and @timestamp:[now-1h TO now]
```

## 3. Houve sucesso depois das falhas? (100112 e 100113)

1. Abrir o evento 4624 e confirmar `targetUserName`, `ipAddress` e `logonType`.
2. Buscar o que a conta fez depois do logon: eventos 4672 (privilégios), 4720 (conta criada),
   4728/4732 (grupos privilegiados) e Sysmon evento 1.
3. Verificar se o usuário real reconhece o logon.

**Sem justificativa legítima, tratar como conta comprometida.**

## 4. Contenção

- Bloquear o IP de origem no firewall, se for externo ou não autorizado.
- Em caso de sucesso (100112/100113): desabilitar a conta ou forçar a troca de senha, encerrar as
  sessões ativas e escalar para N2.
- Para spray: verificar se alguma das contas testadas tem a senha usada; todas as contas alvo devem
  trocar a senha.

## 5. Escalonar para N2

Escalar sempre nos alertas 100112 e 100113, e na 100111 quando a origem for externa. Informar:

- Conta(s) atacada(s), IP de origem e horário do primeiro e do último evento
- Se houve logon com sucesso, de que tipo e a que horas
- Ações que a conta executou depois do sucesso
- Contenção já aplicada

## 6. Falsos positivos conhecidos

- Usuário que digitou a senha errada várias vezes e depois acertou: 100110 e 100112 sem outros indícios.
- Serviço ou tarefa agendada com credencial desatualizada.
- Scanner de vulnerabilidades autorizado.

Registrar o motivo no chamado para que o ajuste da regra (allowlist, limiar) tenha base.
