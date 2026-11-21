# Auditor WiFi — Desafio de Redes (uso didático)

Ferramenta de linha de comando para Ubuntu que automatiza uma auditoria de
rede WiFi **de um único AP escolhido por você**, para um desafio de sala de
aula de uma disciplina de redes.

## ⚠️ Uso autorizado — leia antes

Esta ferramenta só deve ser usada contra:

- **sua própria rede** (para testes), ou
- a **rede do laboratório/sala** configurada explicitamente pelo professor
  para este exercício.

O script **pede confirmação explícita** ("sim") antes de qualquer ataque, e
o alvo é **sempre um único AP escolhido por você** numa lista — nunca
varredura em massa ou ataque automático em tudo que aparece.

## Como roda a escolha do alvo (fluxo)

1. O script faz um scan de ~15s (2.4 GHz + 5 GHz) e mostra uma **lista
   numerada** de redes encontradas (ESSID, BSSID, canal, criptografia,
   força do sinal).
2. Você digita o **número** da rede que quer testar.
3. Antes de atacar, ele pergunta se essa rede é sua/autorizada — só segue
   se você confirmar com `sim`.
4. Depois, perguntas específicas guiam a escolha da rota de ataque (ex.:
   "você conhece parte da senha?").

Nada é decorado nem automático sem sua confirmação em cada etapa.

## Requisitos

- Ubuntu com uma placa WiFi que suporte modo monitor.
- Rodar como root: `sudo ./auditor.sh`
- Internet disponível na primeira execução (para instalar pacotes e baixar
  a wordlist `rockyou.txt` — isso é feito **antes** de entrar em modo
  monitor, porque o modo monitor derruba a internet da máquina).

Dependências instaladas automaticamente se faltarem: `aircrack-ng`,
`reaver`, `pixiewps`, `hashcat`, `crunch`, `hcxtools`.

## Uso

```bash
cd ~/wifi-auditor
sudo ./auditor.sh
```

Menu:

- **[1] Rodar auditoria completa** — descobre dados do AP e tenta obter a
  senha pelas rotas disponíveis (máscara → WPS → dicionário).
- **[2] Só descobrir dados do AP** — ESSID, BSSID, canal, frequência,
  criptografia, sem tentar quebrar a senha. Equivale à flag:
  ```bash
  sudo ./auditor.sh --somente-dados
  ```
- **[3] Sair**

## Lógica de escolha automática do ataque

Executada nesta ordem, parando no primeiro sucesso:

1. **Rota A — Máscara**: se você souber parte da senha (prefixo + tamanho),
   é testada primeiro (muito mais rápida que dicionário).
2. **Rota B — WPS**: se o AP tiver WPS ativo, tenta Pixie Dust e depois
   brute de PIN. Detecta e aborta automaticamente o loop de bloqueio de PIN
   (quando o roteador nunca chega a enviar a mensagem M1).
3. **Rota C — Dicionário + regras**: captura o handshake e tenta
   `rockyou.txt` com regras `best64` via hashcat (GPU) com fallback para
   aircrack-ng (CPU). Se não achar, reporta honestamente que a senha é
   provavelmente forte, com uma estimativa de inviabilidade de brute-force.

## Saída

Ao final, imprime um resumo na tela e salva em `respostas.txt`:

```
================= RESPOSTAS DO DESAFIO =================
ESSID .............: MinhaRedeLab
Frequência ........: 2.4 GHz (2437 MHz aprox.)
Canal .............: 6
MAC do roteador ...: AA:BB:CC:DD:EE:FF
IP do roteador ....: 192.168.1.1
Senha .............: ********
Rota usada ........: Dicionário (aircrack-ng/rockyou)
===========================================================
```

Log completo de toda a execução fica em `auditoria.log` (no mesmo diretório
do script), útil para revisar depois ou debugar falhas.

## Robustez / tratamento de erros

- Interface WiFi detectada automaticamente (`iw dev`), nunca assume
  `wlan0`; se houver mais de uma, pergunta qual usar.
- Nome da interface em modo monitor é descoberto dinamicamente (nunca
  hardcoded como `wlan0mon`); se a interface monitor "desaparecer" no meio
  do processo, o script recria automaticamente.
- Região regulatória ajustada para BR (`iw reg set BR`) para habilitar
  canais 5 GHz/DFS corretamente.
- Se o deauth não funcionar (comum em canais DFS ou redes com PMF/802.11w
  do Wi-Fi 6), o script avisa e pede para você desconectar/reconectar um
  dispositivo manualmente.
- Caracteres especiais na senha (`&`, `$`, `:` etc.) são tratados com
  aspas simples ao salvar/usar.
- Ao final (ou em caso de erro/Ctrl+C), um `trap` garante que a placa
  volta ao modo gerenciado normal e o NetworkManager é religado, para você
  não perder a internet da máquina.

## Alternativa pronta (menos código pra entender, mas mais rápida)

Se o objetivo for só resolver o desafio sem estudar cada etapa, o
[`wifite2`](https://github.com/derv82/wifite2) já implementa boa parte
dessa lógica (auto-seleção WPS/PMKID/handshake + dicionário, com menu de
alvos):

```bash
sudo apt install wifite
sudo wifite
```

Este projeto (`auditor.sh`) foi feito para ser **lido e entendido** —
cada etapa tem comentários explicando o que faz e por quê, pensado para
estudo da disciplina de redes.
