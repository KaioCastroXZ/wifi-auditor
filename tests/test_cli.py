import subprocess
import tempfile
import unittest
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CliFixtureTestCase(unittest.TestCase):
    def _executar_detector(self, visto):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            prefixo = base / "captura"
            bssid = "AA:BB:CC:DD:EE:FF"
            conteudo = (
                "BSSID, First time seen\n\n"
                "Station MAC, First time seen, Last time seen, Power, # packets, BSSID\n"
                f"11:22:33:44:55:66, {visto}, {visto}, -30, 4, {bssid}\n"
            )
            Path(f"{prefixo}-02.csv").write_text(conteudo)
            script = r'''
                source "$4/auditor.sh"
                trap - EXIT INT TERM
                CAPTURE_PREFIX="$1"
                TARGET_BSSID="$2"
                LOGFILE="$3"
                ha_cliente_conectado
            '''
            return subprocess.run(
                ["bash", "-c", script, "_", str(prefixo), bssid, str(base / "log"), str(ROOT)],
                capture_output=True,
                text=True,
            )

    def test_cli_detecta_cliente_no_csv_02_recente(self):
        visto = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        resultado = self._executar_detector(visto)
        self.assertEqual(resultado.returncode, 0, resultado.stderr)

    def test_cli_ignora_associacao_antiga(self):
        resultado = self._executar_detector("2020-01-01 00:00:00")
        self.assertNotEqual(resultado.returncode, 0)


if __name__ == "__main__":
    unittest.main()
