#!/usr/bin/env bash
# validar-e-reiniciar.sh — valida as regras e só reinicia o manager se a sintaxe estiver OK.
# Uso: sudo ./scripts/validar-e-reiniciar.sh

# -e: para no primeiro erro | -u: erro se usar variável não definida | -o pipefail: erro em pipes
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Execute com sudo." >&2
  exit 1
fi

echo "[1/3] Validando regras e decoders..."
# -t = modo teste: carrega toda a configuração e sai, sem processar eventos
if ! /var/ossec/bin/wazuh-analysisd -t; then
  echo "ERRO: sintaxe inválida. O manager NÃO foi reiniciado." >&2
  exit 1
fi

echo "[2/3] Reiniciando wazuh-manager..."
systemctl restart wazuh-manager

echo "[3/3] Status:"
systemctl is-active wazuh-manager
