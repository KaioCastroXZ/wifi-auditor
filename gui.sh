#!/usr/bin/env bash
#
# gui.sh — abre o Auditor WiFi em modo painel web (gráfico).
#
# Roda tudo localmente (http://127.0.0.1:5000): a página abre no seu
# navegador, mas o servidor Flask roda nesta máquina, com root, e é ele
# quem mexe na placa de rede (igual o auditor.sh faz por trás dos panos).
#
set -uo pipefail

WORKDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Este painel precisa rodar como root (mexe direto na placa de rede)."
    echo "Rodando: sudo $0"
    exec sudo "$0" "$@"
fi

if ! dpkg -s python3-flask &>/dev/null; then
    echo "Instalando dependência: python3-flask..."
    apt-get update
    apt-get install -y python3-flask
fi

# Abre o navegador automaticamente assim que o servidor estiver no ar.
# Importante: como este script roda como root (via sudo), "sudo -u <user>"
# sozinho NÃO basta — o sudo reseta DISPLAY/XAUTHORITY por padrão, e sem
# isso o navegador do seu usuário normal nunca recebe o comando (falha
# silenciosa). Por isso descobrimos e repassamos essas variáveis na mão.
USUARIO_REAL="${SUDO_USER:-$USER}"
DISPLAY_REAL="${DISPLAY:-:0}"
XAUTHORITY_REAL="${XAUTHORITY:-/home/${USUARIO_REAL}/.Xauthority}"
DBUS_REAL="unix:path=/run/user/$(id -u "${USUARIO_REAL}")/bus"

(
    for _ in $(seq 1 20); do
        if curl -s -o /dev/null "http://127.0.0.1:5000"; then
            sudo -u "${USUARIO_REAL}" \
                DISPLAY="${DISPLAY_REAL}" \
                XAUTHORITY="${XAUTHORITY_REAL}" \
                DBUS_SESSION_BUS_ADDRESS="${DBUS_REAL}" \
                xdg-open "http://127.0.0.1:5000" &>/tmp/auditor_xdg_open.log \
                || echo ">>> Não consegui abrir o navegador sozinho. Abra manualmente: http://127.0.0.1:5000"
            break
        fi
        sleep 0.5
    done
) &

cd "${WORKDIR}/gui"
exec python3 app.py
