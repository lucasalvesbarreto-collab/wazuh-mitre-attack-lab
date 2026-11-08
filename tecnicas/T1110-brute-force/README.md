# T1110 Brute Force: arquivos pendentes

A documentação desta técnica (regras 100110–100113) foi gerada em uma sessão anterior.
Coloque nesta pasta os arquivos que você já tem:

- [ ] `regra.xml`: bloco `<group>` da T1110 (também pode ser copiado do manager)
- [ ] `simulacao.md`
- [ ] `analise.md`
- [ ] `playbook-N1.md`
- [x] `evidencias/`: JSONs de 100110, 100111 e 100112 já exportados; prints tirados em 07/11

Depois de copiar, apague este README e coloque o bloco `<group>` também em
`rules/local_rules.xml` (no lugar do comentário PENDENTE), ou rode
`sudo ./scripts/exportar-regras.sh` no Ubuntu.

## Achado da rodada de evidências para incluir no `analise.md`

**Sobreposição entre as correlações 100112 e 100113.** No teste "spray + logon correto", o
logon final gerou a **100112** em vez da **100113**. Motivo: o brute force anterior na conta
`usuario.lab` (Testes 1 a 3, 17:15 UTC) ainda estava dentro da janela da 100112, e as duas
correlações casaram com o mesmo evento 4624. Como o Wazuh emite **um alerta por evento**, a
100112 venceu. Na validação original a 100113 disparou porque o spray foi feito sem brute force
recente na mesma conta.

**Causa exata:** as duas regras são irmãs com os mesmos pais (`if_sid 60106,92657`), e o Wazuh
avalia irmãs na ordem do arquivo: a primeira que casa vence. A 100112 vem antes da 100113.

Melhorias possíveis (a primeira é a mais simples: colocar a 100113, mais específica, antes da 100112): tornar a 100113 filha da 100112, ou separar os testes por mais que a janela
da 100112 para validar cada uma isoladamente. A 100113 ficou **sem JSON exportado** nesta rodada.
