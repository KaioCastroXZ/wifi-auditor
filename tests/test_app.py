import sys
import queue
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gui"))
try:
    import app as webapp  # noqa: E402
except ModuleNotFoundError as exc:
    if exc.name != "flask":
        raise
    webapp = None


@unittest.skipIf(webapp is None, "Flask não está instalado neste ambiente")
class ApiValidationTestCase(unittest.TestCase):
    def setUp(self):
        self.client = webapp.app.test_client()
        self._log_original = webapp.engine.log
        webapp.engine.log = lambda _mensagem: None
        with webapp._lock_etapas:
            webapp._etapa_ativa.update(nome=None, thread=None, recuperando=False)
        webapp.engine.alvos = [{
            "essid": "Rede", "bssid": "AA:BB:CC:DD:EE:FF",
            "ch": "6", "enc": "WPA2", "pwr": -40,
        }]
        webapp.engine.target = {}
        webapp.engine.autorizado = False
        webapp.engine.autorizado_bssid = None
        with webapp._subscribers_lock:
            webapp._subscribers.clear()

    def tearDown(self):
        webapp.engine.log = self._log_original

    def test_indice_negativo_e_rejeitado(self):
        resposta = self.client.post("/api/target", json={"idx": -1})
        self.assertEqual(resposta.status_code, 400)

    def test_painel_renderiza(self):
        resposta = self.client.get("/")
        self.assertEqual(resposta.status_code, 200)
        self.assertIn(b"senha", resposta.data.lower())

    def test_autorizacao_exige_booleano_real(self):
        webapp.engine.escolher_alvo(0)
        resposta = self.client.post("/api/authorize", json={"confirmado": "false"})
        self.assertEqual(resposta.status_code, 400)
        self.assertFalse(webapp.engine.autorizado)

    def test_ataque_exige_autorizacao_do_bssid_atual(self):
        webapp.engine.escolher_alvo(0)
        resposta = self.client.post("/api/attack", json={"somente_dados": True})
        self.assertEqual(resposta.status_code, 409)

    def test_target_nao_muda_durante_etapa(self):
        with webapp._lock_etapas:
            webapp._etapa_ativa["nome"] = "scan"
        resposta = self.client.post("/api/target", json={"idx": 0})
        self.assertEqual(resposta.status_code, 409)

    def test_evento_e_entregue_a_todos_os_assinantes(self):
        primeira = queue.Queue()
        segunda = queue.Queue()
        with webapp._subscribers_lock:
            webapp._subscribers.update((primeira, segunda))
        webapp._push("teste", {"valor": 1})
        self.assertEqual(primeira.get_nowait(), segunda.get_nowait())


if __name__ == "__main__":
    unittest.main()
