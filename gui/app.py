#!/usr/bin/env python3
"""
app.py — painel web do Auditor WiFi.

Roda localmente (sudo python3 app.py) e serve uma página em
http://127.0.0.1:5000 — tudo fica na sua máquina, nada sai pra internet
(fora o download da wordlist, igual ao auditor.sh).

Precisa de root pelos mesmos motivos do auditor.sh: airmon-ng, airodump-ng,
nmcli, etc. mexem direto na placa de rede.
"""

import atexit
import fcntl
import json
import os
import queue
import signal
import sys
import threading

from flask import Flask, Response, jsonify, render_template, request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core import Engine  # noqa: E402

app = Flask(__name__)

_subscribers = set()
_subscribers_lock = threading.Lock()
_global_lock_handle = None
LOCK_PATH = "/run/lock/wifi-auditor.lock"


def _push(tipo, dados=None):
    mensagem = json.dumps({"tipo": tipo, "dados": dados or {}})
    with _subscribers_lock:
        filas = list(_subscribers)
    for fila in filas:
        try:
            fila.put_nowait(mensagem)
        except queue.Full:
            try:
                fila.get_nowait()
                fila.put_nowait(mensagem)
            except queue.Empty:
                pass


def _log_cb(linha):
    _push("log", {"linha": linha})


engine = Engine(_log_cb)

_lock_etapas = threading.Lock()
_etapa_ativa = {"nome": None, "thread": None, "recuperando": False}


def _em_thread(fn, *args, **kwargs):
    t = threading.Thread(target=fn, args=args, kwargs=kwargs, daemon=True)
    t.start()
    return t


def _iniciar_etapa_exclusiva(nome, fn, *args, **kwargs):
    """Garante que só uma etapa longa (preparar/monitor/scan/ataque) roda por
    vez. Sem isso, o painel deixa o botão clicável de novo assim que o POST
    volta (bem antes da etapa real terminar em background) — um segundo
    clique dispara, por exemplo, dois 'airmon-ng start' concorrentes na
    mesma placa, o que pode travar o kernel/driver em vez de só devolver
    erro. Retorna False (sem iniciar nada) se já houver uma etapa rodando."""
    with _lock_etapas:
        if _etapa_ativa["nome"] is not None or _etapa_ativa["recuperando"]:
            atual = _etapa_ativa["nome"] or "restauração"
            _push(
                "erro",
                {
                    "mensagem": (
                        f"Já tem uma etapa em andamento ({atual}). "
                        "Aguarde terminar antes de clicar de novo."
                    )
                },
            )
            return False
        def _wrapper():
            engine.iniciar_operacao()
            thread_atual = threading.current_thread()
            try:
                fn(*args, **kwargs)
            finally:
                with _lock_etapas:
                    if _etapa_ativa["thread"] is thread_atual:
                        _etapa_ativa["nome"] = None
                        _etapa_ativa["thread"] = None

        t = threading.Thread(target=_wrapper, daemon=True, name=f"auditor-{nome}")
        _etapa_ativa["nome"] = nome
        _etapa_ativa["thread"] = t

    try:
        t.start()
    except Exception:
        with _lock_etapas:
            _etapa_ativa["nome"] = None
            _etapa_ativa["thread"] = None
        raise
    return True


def _rejeitar_se_ocupado():
    with _lock_etapas:
        nome = _etapa_ativa["nome"]
        recuperando = _etapa_ativa["recuperando"]
    if nome or recuperando:
        return jsonify({"erro": f"Operação em andamento: {nome or 'restauração'}"}), 409
    return None


def _iniciar_recuperacao(forcar):
    with _lock_etapas:
        if _etapa_ativa["recuperando"]:
            return False
        _etapa_ativa["recuperando"] = True
        thread_ativa = _etapa_ativa["thread"]

    def _recuperar():
        try:
            engine.pedir_parada()
            if thread_ativa and thread_ativa is not threading.current_thread():
                thread_ativa.join(timeout=40)
                if thread_ativa.is_alive():
                    _push("erro", {"mensagem": "A etapa não encerrou dentro do prazo de segurança."})
            if forcar:
                engine.restaurar_modo_gerenciado(forcar=True)
            else:
                engine.cleanup()
            _push("restaurado" if forcar else "parado", {})
        except Exception as e:
            _push("erro", {"mensagem": f"Falha ao restaurar a rede: {e}"})
        finally:
            with _lock_etapas:
                _etapa_ativa["recuperando"] = False

    _em_thread(_recuperar)
    return True


def _adquirir_lock_global():
    global _global_lock_handle
    _global_lock_handle = open(LOCK_PATH, "a+")
    try:
        fcntl.flock(_global_lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as e:
        raise RuntimeError("Outra instância do WiFi Auditor já está usando a interface.") from e
    _global_lock_handle.seek(0)
    _global_lock_handle.truncate()
    _global_lock_handle.write(str(os.getpid()))
    _global_lock_handle.flush()


def _validar_mascara(mascara):
    if mascara is None:
        return None
    if not isinstance(mascara, dict):
        return "Máscara inválida."
    if mascara.get("hashcat"):
        if not isinstance(mascara["hashcat"], str) or len(mascara["hashcat"]) > 256:
            return "Máscara hashcat inválida."
        if not isinstance(mascara.get("custom", ""), str):
            return "Charset custom inválido."
        return None
    if mascara.get("mascara"):
        if not isinstance(mascara["mascara"], str) or len(mascara["mascara"]) > 256:
            return "Máscara crunch inválida."
        return None
    tamanho = mascara.get("tamanho")
    prefixo = mascara.get("prefixo", "")
    tipo = mascara.get("tipo", "")
    if isinstance(tamanho, bool) or not isinstance(tamanho, int) or not 1 <= tamanho <= 63:
        return "Tamanho da máscara deve estar entre 1 e 63."
    if not isinstance(prefixo, str) or len(prefixo) > tamanho:
        return "Prefixo da máscara inválido."
    if tipo not in ("%", ",", "@", "^"):
        return "Tipo de coringa inválido."
    return None


# ----------------------------------------------------------------------
# cleanup garantido ao encerrar o processo (Ctrl+C no terminal do servidor)
# ----------------------------------------------------------------------

def _cleanup_e_sair(*_a):
    try:
        engine.cleanup()
    finally:
        os._exit(0)


def _registrar_cleanup_de_processo():
    signal.signal(signal.SIGINT, _cleanup_e_sair)
    signal.signal(signal.SIGTERM, _cleanup_e_sair)
    atexit.register(engine.cleanup)


# ----------------------------------------------------------------------
# páginas / streaming
# ----------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stream")
def stream():
    fila = queue.Queue(maxsize=500)
    with _subscribers_lock:
        _subscribers.add(fila)

    def gerar():
        try:
            yield "retry: 2000\n\n"
            while True:
                try:
                    linha = fila.get(timeout=15)
                    yield f"data: {linha}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"
        finally:
            with _subscribers_lock:
                _subscribers.discard(fila)

    return Response(gerar(), mimetype="text/event-stream")


# ----------------------------------------------------------------------
# etapa 1: preparar (dependências + wordlist + interfaces)
# ----------------------------------------------------------------------

def _tarefa_preparar():
    try:
        engine.verificar_dependencias()
        engine.garantir_wordlist()
        interfaces = engine.detectar_interfaces()
        _push("interfaces", {"lista": interfaces})
    except Exception as e:
        _push("erro", {"mensagem": str(e)})


@app.route("/api/prepare", methods=["POST"])
def api_prepare():
    ok = _iniciar_etapa_exclusiva("preparar", _tarefa_preparar)
    return jsonify({"status": "iniciado" if ok else "ocupado"}), (200 if ok else 409)


# ----------------------------------------------------------------------
# etapa 1b: modo monitor
# ----------------------------------------------------------------------

def _tarefa_monitor(iface):
    try:
        moniface = engine.entrar_modo_monitor(iface)
        _push("monitor_pronto", {"moniface": moniface})
    except Exception as e:
        _push("erro", {"mensagem": str(e)})
        engine.cleanup()


@app.route("/api/monitor", methods=["POST"])
def api_monitor():
    body = request.get_json(silent=True) or {}
    iface = body.get("iface")
    if not isinstance(iface, str) or not iface:
        return jsonify({"erro": "Interface inválida."}), 400
    ok = _iniciar_etapa_exclusiva("modo monitor", _tarefa_monitor, iface)
    return jsonify({"status": "iniciado" if ok else "ocupado"}), (200 if ok else 409)


# ----------------------------------------------------------------------
# etapa 2: scan
# ----------------------------------------------------------------------

def _tarefa_scan():
    try:
        aps = engine.escanear()
        _push("scan_resultado", {"aps": aps})
    except Exception as e:
        _push("erro", {"mensagem": str(e)})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    ok = _iniciar_etapa_exclusiva("scan", _tarefa_scan)
    return jsonify({"status": "iniciado" if ok else "ocupado"}), (200 if ok else 409)


@app.route("/api/target", methods=["POST"])
def api_target():
    ocupado = _rejeitar_se_ocupado()
    if ocupado:
        return ocupado
    body = request.get_json(silent=True) or {}
    idx = body.get("idx")
    if isinstance(idx, bool) or not isinstance(idx, int):
        return jsonify({"erro": "Índice de alvo inválido."}), 400
    try:
        alvo = engine.escolher_alvo(idx)
    except (IndexError, ValueError) as e:
        return jsonify({"erro": str(e)}), 400
    _push("alvo_escolhido", {"alvo": alvo})
    return jsonify({"status": "ok", "alvo": alvo})


# ----------------------------------------------------------------------
# etapa 3: autorização
# ----------------------------------------------------------------------

@app.route("/api/authorize", methods=["POST"])
def api_authorize():
    ocupado = _rejeitar_se_ocupado()
    if ocupado:
        return ocupado
    body = request.get_json(silent=True) or {}
    confirmado = body.get("confirmado")
    if type(confirmado) is not bool:
        return jsonify({"erro": "O campo confirmado deve ser booleano."}), 400
    try:
        ok = engine.autorizar(confirmado)
    except RuntimeError as e:
        return jsonify({"erro": str(e)}), 409
    _push("autorizado", {"ok": ok})
    return jsonify({"status": "ok", "autorizado": ok})


# ----------------------------------------------------------------------
# etapa 4: ataque
# ----------------------------------------------------------------------

def _tarefa_ataque(mascara, somente_dados):
    try:
        engine.iniciar_tentativa()
        if not somente_dados:
            engine.executar_ataque(mascara=mascara)
            if engine._parar:
                return
            if engine.senha:
                engine.conectar_e_obter_gateway()
        resumo = engine.resumo()
        _push("ataque_finalizado", {"resumo": resumo})
    except Exception as e:
        _push("erro", {"mensagem": str(e)})
    finally:
        engine.cleanup()
        _push("limpeza_concluida", {})


@app.route("/api/attack", methods=["POST"])
def api_attack():
    body = request.get_json(silent=True) or {}
    somente_dados = body.get("somente_dados", False)
    if type(somente_dados) is not bool:
        return jsonify({"erro": "somente_dados deve ser booleano."}), 400
    mascara = body.get("mascara")  # {tamanho, prefixo, tipo} ou None
    erro_mascara = _validar_mascara(mascara)
    if erro_mascara:
        return jsonify({"erro": erro_mascara}), 400
    if not engine.target.get("bssid"):
        return jsonify({"erro": "Selecione um alvo antes de iniciar."}), 409
    if not engine.autorizacao_valida():
        return jsonify({"erro": "Autorize explicitamente o BSSID selecionado."}), 409
    ok = _iniciar_etapa_exclusiva("ataque", _tarefa_ataque, mascara, somente_dados)
    return jsonify({"status": "iniciado" if ok else "ocupado"}), (200 if ok else 409)


@app.route("/api/stop", methods=["POST"])
def api_stop():
    _push("log", {"linha": "Parada de emergência solicitada pelo painel..."})
    if not _iniciar_recuperacao(forcar=False):
        return jsonify({"status": "já parando"}), 409
    return jsonify({"status": "parando"})


# ----------------------------------------------------------------------
# botão de emergência: restaurar minha rede
# funciona em qualquer momento do fluxo, mesmo se algo travou antes
# ----------------------------------------------------------------------

@app.route("/api/restore", methods=["POST"])
def api_restore():
    _push("log", {"linha": "Restaurando sua rede (modo gerenciado + NetworkManager)..."})
    if not _iniciar_recuperacao(forcar=True):
        return jsonify({"status": "já restaurando"}), 409
    return jsonify({"status": "restaurando"})


if __name__ == "__main__":
    if os.geteuid() != 0 and not os.environ.get("AUDITOR_ALLOW_NO_ROOT"):
        print("ERRO: rode este painel como root (sudo python3 app.py) — precisa")
        print("mexer direto na placa de rede (airmon-ng, airodump-ng, nmcli, etc.).")
        sys.exit(1)

    try:
        _adquirir_lock_global()
    except RuntimeError as e:
        print(f"ERRO: {e}")
        sys.exit(1)

    _registrar_cleanup_de_processo()
    print("Painel disponível em: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, threaded=True)
