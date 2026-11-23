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
`reaver`, `pixiewps`, `hashcat`, `crunch`, `hcxtools`, `hcxdumptool`,
`tcpdump`.

## Uso

```bash
cd ~/wifi-auditor
sudo ./auditor.sh
```

Menu:

- **[1] Rodar auditoria completa** — descobre dados do AP e tenta obter a
  senha pelas rotas disponíveis (máscara → WPS → PMKID → dicionário).
- **[2] Só descobrir dados do AP** — ESSID, BSSID, canal, frequência,
  criptografia, sem tentar quebrar a senha. Equivale à flag:
  ```bash
  sudo ./auditor.sh --somente-dados
  ```
- **[3] Sair**

### Botão de emergência (restaurar a rede)

Se uma execução travar e a internet não voltar, rode:

```bash
sudo ./auditor.sh --restaurar
```

Isso força a placa de volta ao modo gerenciado e religa o NetworkManager,
independente do estado em que o script tenha parado.

## Lógica de escolha automática do ataque

Executada nesta ordem, parando no primeiro sucesso:

1. **Rota A — Máscara**: se você souber parte da senha, é testada primeiro
   (muito mais rápida que dicionário). Veja **Rota A em detalhe** abaixo.
2. **Rota B — WPS**: se o AP tiver WPS ativo, tenta Pixie Dust e depois
   brute de PIN. Detecta e aborta automaticamente o loop de bloqueio de PIN
   (quando o roteador nunca chega a enviar a mensagem M1).
3. **Rota D — PMKID**: tenta capturar o PMKID direto do roteador com
   `hcxdumptool` (não precisa de cliente conectado nem de deauth) e quebra
   com hashcat. Alguns APs respondem na hora; WPA3/PMF normalmente bloqueiam.
4. **Rota C — Dicionário + regras**: captura o handshake e tenta
   `rockyou.txt` com regras `best64` via hashcat (GPU) com fallback para
   aircrack-ng (CPU). Se não achar, reporta honestamente que a senha é
   provavelmente forte, com uma estimativa de inviabilidade de brute-force.

> A Rota A só roda se você responder `sim` à pergunta "você conhece parte da
> senha?". As rotas B → D → C rodam em sequência automática até uma dar certo.

## Rota A em detalhe — máscaras

A Rota A testa senhas que seguem um padrão que você **já conhece em parte** —
muito mais rápido que varrer um dicionário inteiro. Ao responder `sim` em
"você conhece parte da senha?", aparecem **3 formas** de montar a máscara.

### [1] Máscara completa do crunch

Você digita a máscara inteira, com a parte conhecida em **qualquer** posição
(começo, meio ou fim). Cada coringa representa **uma classe** de caractere
(convenção do `crunch`):

| Coringa | Substitui por |
|---|---|
| `%` | número `0–9` |
| `,` | letra maiúscula `A–Z` |
| `@` | letra minúscula `a–z` |
| `^` | símbolo `!@#$%…` |

Qualquer outro caractere fica **fixo** naquela posição. Para usar um coringa
como literal (ex.: um `@` de verdade na senha), escape com `\` → `\@`.

**Exemplo** — você sabe que a senha é `HEX`, depois 2 dígitos, depois `123`,
depois 2 dígitos:

```
Máscara: HEX%%123%%
```

O tamanho (10) é calculado sozinho e o script roda, por baixo:

```bash
crunch 10 10 -t 'HEX%%123%%' | aircrack-ng -w - -b <BSSID> <captura>
```

Isso testa de `HEX00123` a `HEX99` com os 4 dígitos variando — 10⁴ = 10.000
combinações, praticamente instantâneo.

### [2] Modo guiado

Para o caso simples "sei o começo e o resto é tudo de uma classe só". Você
informa o **tamanho total**, o **prefixo conhecido** e escolhe **uma classe**
para preencher o resto. Ex.: prefixo `CRIPTO`, tamanho 12, resto números →
monta `CRIPTO%%%%%%` automaticamente.

### [3] Máscara hashcat (coringa `?a` = qualquer caractere)

Use quando você **não sabe a classe** de alguma posição. O `crunch` não tem
coringa "qualquer", mas o `hashcat` tem. Coringas:

| Coringa | Substitui por |
|---|---|
| `?d` | dígito |
| `?l` | minúscula |
| `?u` | maiúscula |
| `?s` | símbolo |
| `?a` | **qualquer** um dos acima (95 caracteres) |

**Exemplo** — você sabe `HEX`, depois 2 posições que **podem ser qualquer
coisa**, depois `12`, depois mais 2 quaisquer:

```
Máscara hashcat: HEX?a?a12?a?a
```

O script captura o handshake, converte com `hcxpcapngtool` e roda:

```bash
hashcat -m 22000 <hash> -a 3 'HEX?a?a12?a?a'
```

Usa a **GPU** por padrão; se não houver GPU/driver OpenCL, repete sozinho
com `--force` (CPU, bem mais lento).

**Atenção ao custo:** cada `?a` são 95 possibilidades. `HEX?a?a12?a?a`
(4 posições quaisquer) = 95⁴ ≈ **81 milhões** de tentativas — minutos numa
GPU, lento na CPU. Se você souber que as posições são só letras + números
(sem símbolo), reduza com um charset custom:

```
Máscara hashcat: HEX?1?112?1?1
Charset ?1:      ?l?u?d
```

→ 62⁴ ≈ 14 milhões (bem mais rápido).

### Qual modo usar?

- **Sei a classe** de cada posição desconhecida (ex.: "são todos dígitos") →
  crunch (modo 1 ou 2), mais rápido.
- **Não faço ideia** da classe de alguma posição → hashcat `?a` (modo 3).

> Importante: a Rota A, em qualquer modo, precisa de um **handshake
> capturado** antes de testar as senhas — então o dispositivo-alvo precisa
> conectar ou reconectar à rede enquanto a captura roda. E lembre que
> WPA/WPA2 exige senha de **8+ caracteres**: máscaras menores que isso são
> avisadas e não casam.

## Painel web (opcional)

Além do CLI, há um painel web local (pasta `gui/`) com os mesmos passos em
botões e log ao vivo:

```bash
pip install flask        # dependência do painel
sudo python3 gui/app.py  # abre em http://127.0.0.1:5000
```

Roda tudo **na sua máquina** (nada sai pra internet além do download da
wordlist). Os passos são os mesmos do CLI — inclusive os 3 modos de máscara
da Rota A — e há um botão "Restaurar minha rede" para emergência. Os
endpoints longos são serializados por um lock, pra um segundo clique não
disparar dois comandos concorrentes na mesma placa.

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

> Os comandos sensíveis e mensagens de sucesso têm a senha redigida do log.
> Ainda assim, não commite `auditoria.log`, `auditoria_gui.log`, capturas ou
> `respostas.txt` em repositório público: esses arquivos contêm identificadores
> da rede e o resumo pode conter a senha descoberta.

## Testes simulados

Os testes não usam rádio nem enviam quadros Wi-Fi. Eles exercitam parsers,
estado, autorização, cancelamento e endpoints com fixtures locais:

```bash
python3 -m unittest discover -s tests -v
```

Os testes de API são ignorados automaticamente quando o Flask não está
instalado; `gui.sh` continua instalando essa dependência para executar o painel.

## Robustez / tratamento de erros

- Interface WiFi detectada automaticamente (`iw dev`), nunca assume
  `wlan0`; se houver mais de uma, pergunta qual usar.
- Nome da interface em modo monitor é descoberto dinamicamente (nunca
  hardcoded como `wlan0mon`), comparando um snapshot de interfaces antes e
  depois do `airmon-ng` — assim não pega uma interface monitor "fantasma"
  deixada por uma execução anterior que travou. Se a interface monitor
  "desaparecer" no meio do processo, o script recria automaticamente.
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
