# Análise: T1110 Brute Force

## Objetivo

Detectar tentativas repetidas de adivinhar credenciais (tática de **Credential Access**) e,
principalmente, o momento em que uma delas **dá certo**, que é quando o alerta vira incidente.

## Mapeamento MITRE ATT&CK

| Técnica | Tática | Regras |
|---|---|---|
| T1110.001 Password Guessing | Credential Access | 100110 |
| T1110.003 Password Spraying | Credential Access | 100111 |
| T1110 + T1078 Valid Accounts | Credential Access / Defense Evasion | 100112, 100113 |

## Regras

| ID | Nível | Pai | Lógica |
|---|---|---|---|
| 100110 | 10 | 60122 (`if_matched_sid`) | 5 ou mais falhas (4625) para o **mesmo usuário** em 120 s (`same_field targetUserName`) |
| 100111 | 12 | 60122 (`if_matched_sid`) | 6 ou mais falhas em 180 s, da **mesma origem** (`same_field ipAddress`) para **usuários diferentes** (`different_field targetUserName`) |
| 100112 | 14 | 60106, 92657 | Logon com sucesso na conta que já disparou a 100110, em até 600 s |
| 100113 | 14 | 60106, 92657 | Logon com sucesso da origem que já disparou a 100111, em até 600 s |

### Por que dois padrões

- **Brute force** insiste em uma conta: muitas senhas, um usuário. A 100110 agrupa por usuário.
- **Spray** inverte a lógica: uma senha, muitos usuários, para ficar abaixo do bloqueio de conta.
  A 100111 agrupa por origem e exige usuários distintos.
- Os limiares (5 em 2 min; 6 usuários em 3 min) são decisões de negócio: baixos geram ruído
  com usuários que erram a senha; altos deixam passar ataques lentos.

## Resultados dos testes (07/11/2026)

| # | Teste | Esperado | Resultado |
|---|---|---|---|
| 1 | 8 falhas na mesma conta | 100110 | ✅ 100110 |
| 2 | 3 falhas na mesma conta (negativo) | só 60122 | ✅ nenhuma 100110 |
| 3 | 8 falhas + logon correto | 100112 | ✅ 100112 |
| 4 | Spray com 7 usuários | 100111 | ✅ 100111 no 6º usuário distinto |
| 5 | Spray + logon correto | 100113 | ⚠️ **100112** disparou no lugar da 100113 |

## Sobreposição 100112 × 100113

No Teste 5 o logon correto casou com as duas regras: a conta tinha a 100110 recente (100112)
e a origem tinha a 100111 recente (100113). Como o Wazuh emite **um alerta por evento** e regras
irmãs são avaliadas na ordem em que foram carregadas, apareceu só a 100112. Os dois alertas têm
o mesmo nível (14) e sinalizam o mesmo risco, mas a descrição não mostra que houve também spray.
A regra 100113 foi validada em sessão anterior à rodada de evidências.

## Ruído e falsos positivos

| Origem | Causa | Tratamento |
|---|---|---|
| Usuário que esqueceu a senha | 5 falhas em 2 min na própria conta | Verificar `ipAddress` e `workstationName`; conferir se o logon seguinte veio da mesma estação |
| Serviço com senha desatualizada | Falhas repetidas e regulares de uma conta de serviço | Corrigir a credencial; ajustar o limiar por conta se necessário |
| Scanner de vulnerabilidade | Muitas contas testadas de um IP conhecido | Allowlist do IP do scanner |

## Limitações

- Origem `127.0.0.1` nos testes locais: em produção o `ipAddress` identifica a máquina de origem
  e é o que torna a 100111 útil.
- Spray lento, com um usuário a cada poucos minutos, fica fora da janela de 180 s.
- `same_field` e `different_field` exigem que o campo exista no evento; falhas por Kerberos
  (4771) não são cobertas por estas regras.
- A 100112 só correlaciona logons dentro de 600 s da 100110.

## Melhorias futuras

- Diferenciar na descrição o caso em que o logon casa com brute force **e** spray.
- Cobrir falhas de pré-autenticação Kerberos (4771).
- Janelas mais longas para spray lento.
- Converter as regras para Sigma.

## Lições aprendidas

1. **Regras irmãs sob os mesmos pais competem.** Dois alertas de correlação possíveis para o mesmo
   evento resultam em apenas um.
2. **`different_field` é o que separa spray de brute force.** Sem ele, a 100111 dispararia para uma
   conta atacada muitas vezes.
3. **O limiar é uma decisão de negócio**, não só técnica.
4. **O teste negativo prova a regra.** Três falhas não disparam a 100110.

## Evidências

Prints do dashboard em `evidencias/`:

- `T1110-01-100110-8-falhas.png`: 100110 expandida, evento 4625 com `targetUserName` e `ipAddress`
- `T1110-02-negativo-3-falhas.png`: três falhas sem a 100110
- `T1110-03-falhas-seguidas-de-logon.png`: 100110 seguida da 100112
- `T1110-04-spray-100111.png`: spray no Ubuntu e a 100111
- `T1110-05-spray-logon-100112-sobreposicao.png`: spray seguido de logon, com a 100112
