import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gui"))
import core  # noqa: E402


class EngineTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.patches = [
            mock.patch.object(core, "WORKDIR", self.base),
            mock.patch.object(core, "LOGFILE", self.base / "auditoria.log"),
            mock.patch.object(core, "RESPOSTAS", self.base / "respostas.txt"),
            mock.patch.object(core, "CAPTURE_PREFIX", self.base / "captura_gui"),
            mock.patch.object(core, "SCAN_PREFIX", self.base / "scan_gui"),
            mock.patch.object(core, "WORDLIST_DIR", self.base / "wordlists"),
            mock.patch.object(core, "ROCKYOU", self.base / "wordlists" / "rockyou.txt"),
        ]
        for patcher in self.patches:
            patcher.start()
        self.engine = core.Engine(lambda _linha: None)

    def tearDown(self):
        self.engine.pedir_parada()
        for patcher in reversed(self.patches):
            patcher.stop()
        self.tmp.cleanup()

    @staticmethod
    def _ap_csv(bssid="AA:BB:CC:DD:EE:FF", essid="Rede Teste"):
        return (
            "BSSID, First time seen, Last time seen, channel, Speed, Privacy, "
            "Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
            f"{bssid}, 2026-11-23 10:00:00, 2026-11-23 10:00:01, 6, 54, WPA2, "
            f"CCMP, PSK, -42, 10, 0, 0.0.0.0, {len(essid)}, {essid},\n"
            "\nStation MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\n"
        )

    def test_parser_retorna_ap_e_contagem_de_rejeitados(self):
        texto = self._ap_csv().replace(
            "\nStation MAC", "\nAA:BB:CC:DD:EE:GG, linha, incompleta\n\nStation MAC"
        )
        aps, rejeitadas = self.engine._parsear_scan_csv(texto)
        self.assertEqual([ap["bssid"] for ap in aps], ["AA:BB:CC:DD:EE:FF"])
        self.assertEqual(aps[0]["essid"], "Rede Teste")
        self.assertEqual(rejeitadas, 1)

    def test_novo_alvo_invalida_autorizacao_e_resultados(self):
        self.engine.alvos = [{
            "essid": "Rede", "bssid": "AA:BB:CC:DD:EE:FF",
            "ch": "6", "enc": "WPA2", "pwr": -40,
        }]
        self.engine.autorizado = True
        self.engine.autorizado_bssid = "11:22:33:44:55:66"
        self.engine.senha = "antiga"
        self.engine.rota_usada = "antiga"
        self.engine.escolher_alvo(0)
        self.assertFalse(self.engine.autorizado)
        self.assertIsNone(self.engine.autorizado_bssid)
        self.assertIsNone(self.engine.senha)
        self.assertIsNone(self.engine.rota_usada)

    def test_resumo_exibe_senha_da_sessao_atual(self):
        self.engine.target = {
            "essid": "Rede", "bssid": "AA:BB:CC:DD:EE:FF",
            "ch": "6", "freq_label": "2.4 GHz",
        }
        self.engine.senha = "senha-da-prova"
        resumo = self.engine.resumo()
        self.assertEqual(resumo["senha"], "senha-da-prova")
        self.assertIn("Senha .............: senha-da-prova", resumo["texto"])
        self.assertIn("senha-da-prova", core.RESPOSTAS.read_text())

    def test_nova_tentativa_remove_senha_e_handshake_anteriores(self):
        self.engine.target = {"bssid": "AA:BB:CC:DD:EE:FF"}
        self.engine.autorizar(True)
        self.engine.senha = "senha-antiga"
        self.engine.rota_usada = "rota-antiga"
        self.engine._capture_path = self.base / "captura-antiga.cap"
        self.engine._capture_bssid = self.engine.target["bssid"]
        self.engine.iniciar_tentativa()
        self.assertIsNone(self.engine.senha)
        self.assertIsNone(self.engine.rota_usada)
        self.assertIsNone(self.engine._capture_path)
        self.assertTrue(self.engine.autorizacao_valida())

    def test_autorizacao_pertence_ao_bssid(self):
        self.engine.target = {"bssid": "AA:BB:CC:DD:EE:FF"}
        self.assertTrue(self.engine.autorizar(True))
        self.assertTrue(self.engine.autorizacao_valida())
        self.engine.target = {"bssid": "11:22:33:44:55:66"}
        self.assertFalse(self.engine.autorizacao_valida())
        self.assertFalse(self.engine.autorizar("false"))

    def test_cliente_e_lido_do_csv_mais_recente(self):
        bssid = "AA:BB:CC:DD:EE:FF"
        self.engine.target = {"bssid": bssid}
        agora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conteudo = (
            "BSSID, First time seen\n\n"
            "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\n"
            f"11:22:33:44:55:66, {agora}, {agora}, -30, 4, {bssid},\n"
        )
        Path(f"{core.CAPTURE_PREFIX}-02.csv").write_text(conteudo)
        self.assertTrue(self.engine.ha_cliente_conectado())

    def test_selecao_de_csv_ignora_formato_kismet(self):
        base = self.base / "scan_gui-01.csv"
        auxiliar = self.base / "scan_gui-01.kismet.csv"
        base.write_text(self._ap_csv())
        time.sleep(0.01)
        auxiliar.write_text("auxiliar")
        escolhido = self.engine._arquivo_mais_recente("scan_gui-[0-9]*.csv")
        self.assertEqual(escolhido, base)

    def test_csv_de_cliente_antigo_nao_dispara_estado_conectado(self):
        bssid = "AA:BB:CC:DD:EE:FF"
        self.engine.target = {"bssid": bssid}
        conteudo = (
            "Station MAC, First time seen, Last time seen, Power, # packets, BSSID\n"
            f"11:22:33:44:55:66, 2020-01-01 00:00:00, 2020-01-01 00:00:01, -30, 4, {bssid}\n"
        )
        Path(f"{core.CAPTURE_PREFIX}-03.csv").write_text(conteudo)
        self.assertFalse(self.engine.ha_cliente_conectado())

    def test_handshake_validado_e_reutilizado(self):
        cap = self.base / "captura_gui-01.cap"
        cap.write_bytes(b"fixture")
        self.engine.target = {"bssid": "AA:BB:CC:DD:EE:FF", "ch": "6"}
        self.engine._capture_path = cap
        self.engine._capture_bssid = self.engine.target["bssid"]
        with mock.patch.object(self.engine, "garantir_moniface_viva"), mock.patch.object(
            self.engine, "_tem_handshake", return_value=True
        ), mock.patch("core.subprocess.Popen") as popen:
            self.assertTrue(self.engine.capturar_handshake())
            popen.assert_not_called()

    def test_deauth_distingue_conclusao_de_falha(self):
        self.engine.target = {"bssid": "AA:BB:CC:DD:EE:FF"}
        self.engine.moniface = "wlan0mon"
        with mock.patch.object(
            self.engine, "run", return_value=subprocess.CompletedProcess([], 1, "", "erro")
        ):
            self.assertFalse(self.engine._executar_deauth_diagnostico())
            self.assertEqual(self.engine.deauth_estado, "falhou")

    def test_cleanup_nao_reinicia_rede_ja_restaurada(self):
        self.engine.monitor_ativo = False
        self.engine.rede_interrompida = False
        with mock.patch.object(self.engine, "run") as executar:
            self.engine.cleanup()
            executar.assert_not_called()

    def test_pedir_parada_interrompe_subprocesso_registrado(self):
        resultado = []

        def executar():
            try:
                self.engine.run(["/bin/sleep", "10"], timeout=30)
            except core.AttackAborted:
                resultado.append("interrompido")

        thread = threading.Thread(target=executar)
        thread.start()
        time.sleep(0.2)
        self.engine.pedir_parada()
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(resultado, ["interrompido"])


if __name__ == "__main__":
    unittest.main()
