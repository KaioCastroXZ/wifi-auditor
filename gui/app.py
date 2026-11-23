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

_log_queue: "queue.Queue[str]" = queue.Queue()


def _push(tipo, dados=None):
    _log_queue.put(json.dumps({"tipo": tipo, "dados": dados or {}}))


def _log_cb(linha):
    _push("log", {"linha": linha})


engine = Engine(_log_cb)

_lock_etapas = threading.Lock()
_etapa_ativa = {"nome": None}


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
        if _etapa_ativa["nome"] is not None:
            _push(
                "erro",
                {
                    "mensagem": (
                        f"Já tem uma etapa em andamento ({_etapa_ativa['nome']}). "
                        "Aguarde terminar antes de clicar de novo."
                    )
                },
            )
            return False
        _etapa_ativa["nome"] = nome

    def _wrapper():
        try:
            fn(*args, **kwargs)
        finally:
            with _lock_etapas:
                _etapa_ativa["nome"] = None

    _em_thread(_wrapper)
    return True


# ----------------------------------------------------------------------
# cleanup garantido ao encerrar o processo (Ctrl+C no terminal do servidor)
# ----------------------------------------------------------------------

def _cleanup_e_sair(*_a):
    try:
        engine.cleanup()
    finally:
        os._exit(0)


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
    def gerar():
        yield "retry: 2000\n\n"
        while True:
            linha = _log_queue.get()
            yield f"data: {linha}\n\n"

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


@app.route("/api/monitor", methods=["POST"])
def api_monitor():
    iface = request.json.get("iface")
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
    idx = int(request.json.get("idx"))
    alvo = engine.escolher_alvo(idx)
    _push("alvo_escolhido", {"alvo": alvo})
    return jsonify({"status": "ok", "alvo": alvo})


# ----------------------------------------------------------------------
# etapa 3: autorização
# ----------------------------------------------------------------------

@app.route("/api/authorize", methods=["POST"])
def api_authorize():
    confirmado = bool(request.json.get("confirmado"))
    ok = engine.autorizar(confirmado)
    _push("autorizado", {"ok": ok})
    return jsonify({"status": "ok", "autorizado": ok})


# ----------------------------------------------------------------------
# etapa 4: ataque
# ----------------------------------------------------------------------

def _tarefa_ataque(mascara, somente_dados):
    try:
        if not somente_dados:
            engine.executar_ataque(mascara=mascara)
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
    body = request.json or {}
    somente_dados = bool(body.get("somente_dados"))
    mascara = body.get("mascara")  # {tamanho, prefixo, tipo} ou None
    engine._parar = False
    ok = _iniciar_etapa_exclusiva("ataque", _tarefa_ataque, mascara, somente_dados)
    return jsonify({"status": "iniciado" if ok else "ocupado"}), (200 if ok else 409)


@app.route("/api/stop", methods=["POST"])
def api_stop():
    engine.pedir_parada()
    _push("log", {"linha": "Parada de emergência solicitada pelo painel..."})

    def _parar_e_limpar():
        engine.cleanup()
        _push("parado", {})

    _em_thread(_parar_e_limpar)
    return jsonify({"status": "parando"})


# ----------------------------------------------------------------------
# botão de emergência: restaurar minha rede
# funciona em qualquer momento do fluxo, mesmo se algo travou antes
# ----------------------------------------------------------------------

def _tarefa_restaurar():
    try:
        engine.pedir_parada()
        engine.restaurar_modo_gerenciado()
        _push("restaurado", {})
    except Exception as e:
        _push("erro", {"mensagem": f"Falha ao restaurar a rede: {e}"})


@app.route("/api/restore", methods=["POST"])
def api_restore():
    _push("log", {"linha": "Restaurando sua rede (modo gerenciado + NetworkManager)..."})
    _em_thread(_tarefa_restaurar)
    return jsonify({"status": "restaurando"})


if __name__ == "__main__":
    if os.geteuid() != 0 and not os.environ.get("AUDITOR_ALLOW_NO_ROOT"):
        print("ERRO: rode este painel como root (sudo python3 app.py) — precisa")
        print("mexer direto na placa de rede (airmon-ng, airodump-ng, nmcli, etc.).")
        sys.exit(1)

    print("Painel disponível em: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, threaded=True)
