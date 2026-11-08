#!/usr/bin/env bash
# exportar-regras.sh — copia o local_rules.xml do manager para o repositório.
# O arquivo do manager é a fonte da verdade; rode isto antes de cada commit de regras.
# Uso (na raiz do repo, no Ubuntu): sudo ./scripts/exportar-regras.sh

set -euo pipefail

ORIGEM="/var/ossec/etc/rules/local_rules.xml"
DESTINO="rules/local_rules.xml"

cp "$ORIGEM" "$DESTINO"

# O arquivo copiado pelo root fica com dono root; devolve ao usuário que chamou o sudo
chown "${SUDO_USER:-$USER}": "$DESTINO"

echo "Copiado: $ORIGEM -> $DESTINO"
echo "Regras encontradas:"
grep -o 'rule id="[0-9]*"' "$DESTINO" | tr '\n' ' '
echo
