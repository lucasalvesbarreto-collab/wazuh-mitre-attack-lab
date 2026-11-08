#!/usr/bin/env bash
# exportar-evidencias.sh — salva o JSON do alerta mais recente de cada regra
# na pasta evidencias/ da técnica correspondente.
# Uso (na raiz do repo, no Ubuntu): sudo ./scripts/exportar-evidencias.sh

set -euo pipefail

ALERTS="/var/ossec/logs/alerts/alerts.json"

# Mapa: faixa de regras -> pasta da técnica
declare -A PASTA=(
  [10011]="tecnicas/T1110-brute-force"
  [10012]="tecnicas/T1136.002-create-domain-account"
  [10013]="tecnicas/T1059.001-powershell"
)

for rid in 100110 100111 100112 100113 \
           100120 100121 100122 100123 100124 100125 100126 \
           100130 100131 100132 100133 100134 100135; do

  # 100122-100126 são da T1098, não da T1136.002
  if (( rid >= 100122 && rid <= 100126 )); then
    dir="tecnicas/T1098-account-manipulation"
  else
    dir="${PASTA[${rid:0:5}]}"
  fi

  # grep -F: busca literal; tail -n 1: alerta mais recente
  linha=$(grep -F "\"id\":\"${rid}\"" "$ALERTS" | tail -n 1 || true)

  if [[ -z "$linha" ]]; then
    echo "  -  ${rid}: nenhum alerta no alerts.json atual"
    continue
  fi

  saida="${dir}/evidencias/alerta-${rid}.json"
  echo "$linha" | python3 -m json.tool > "$saida"
  chown "${SUDO_USER:-$USER}": "$saida"
  echo "  OK ${rid}: ${saida}"
done

echo
echo "ATENÇÃO: revise os JSONs antes do commit (IPs, nomes de host e usuários do lab)."
