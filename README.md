# Traffic Analyzer

Aplicação em Python que captura pacotes de uma interface de rede, grava cada pacote em um banco de dados e exibe estatísticas básicas do tráfego: total de pacotes, pacotes por protocolo e os 5 IPs de origem e de destino com mais tráfego. Roda em Docker.

---

## 1. Visão geral da arquitetura

```
 Interface de rede (eth0, wlan0, ...)
            │  raw socket (AF_PACKET)
            ▼
 ┌──────────────────────┐   callback por pacote   ┌──────────────┐
 │ AsyncSniffer (Scapy) │ ───────────────────────▶ │ parse_packet │ → PacketRecord
 │   thread de captura  │                          └──────┬───────┘
 └──────────────────────┘                                 │
                                    ┌─────────────────────┼──────────────────┐
                                    ▼                                        ▼
                         ┌────────────────────┐                  ┌─────────────────────┐
                         │ LiveStats (memória)│                  │ Fila → PacketWriter │
                         │ painel "ao vivo"   │                  │ (thread, em lotes)  │
                         └────────────────────┘                  └──────────┬──────────┘
                                                                            ▼
                                                                  ┌──────────────────┐
                                                                  │ SQLite (/data)   │
                                                                  └────────┬─────────┘
                                                                           ▼
                                                        compute_stats (SQL) → relatório final
```

Três threads trabalham juntas. A **thread de captura** (Scapy) recebe os pacotes e chama um callback curto que extrai os campos e enfileira o registro. A **thread de escrita** esvazia a fila e grava no banco em lotes. A **thread principal** espera o fim da captura, mostra o painel ao vivo periodicamente e, no final, calcula o relatório com SQL.

### Estrutura de arquivos

```
traffic-analyzer/
├── app/
│   ├── main.py        # CLI (argparse) e orquestração da captura
│   ├── parser.py      # pacote Scapy → PacketRecord (IP origem/destino, protocolo, tamanho)
│   ├── database.py    # schema e acesso ao SQLite
│   ├── writer.py      # thread que grava os pacotes em lotes
│   ├── stats.py       # estatísticas via SQL e contadores ao vivo
│   └── report.py      # formatação das tabelas no terminal
├── tests/             # testes com pacotes sintéticos (não precisam de rede/root)
├── data/              # banco SQLite (montado como volume no container)
├── Dockerfile
├── docker-compose.yml
├── requirements.txt / requirements-dev.txt
└── README.md
```

---

## 2. Pré-requisitos

- Docker 20.10+ e Docker Compose v2 (`docker compose`).
- **Host Linux** para capturar o tráfego real da máquina. Em Docker Desktop (Windows/macOS), `network_mode: host` aponta para a VM interna do Docker, então você verá o tráfego dos containers, não o da sua placa de rede (veja a seção 8).

---

## 3. Como configurar e executar

### 3.1 Build da imagem

```bash
cd traffic-analyzer
docker compose build
```

### 3.2 Descobrir o nome da interface

```bash
docker compose run --rm analyzer interfaces
```

Saída de exemplo:

```
Interfaces disponíveis:
  lo
  eth0  (padrão)
  docker0
```

### 3.3 Capturar

```bash
# Captura por 60 segundos na eth0
docker compose run --rm analyzer capture -i eth0 -t 60

# Captura 1000 pacotes, só TCP e UDP
docker compose run --rm analyzer capture -i eth0 -c 1000 -f "tcp or udp"

# Captura até apertar Ctrl+C, atualizando o painel a cada 10 s
docker compose run --rm analyzer capture -i eth0 --live-interval 10
```

Para gerar tráfego durante o teste, em outro terminal rode, por exemplo, `curl https://example.com` ou `ping -c 20 8.8.8.8`.

Também é possível definir a interface por variável de ambiente: `INTERFACE=eth0 docker compose run --rm analyzer capture -t 30`.

### 3.4 Consultar estatísticas e sessões depois da captura

```bash
docker compose run --rm analyzer sessions            # lista as capturas gravadas
docker compose run --rm analyzer stats               # sessão mais recente
docker compose run --rm analyzer stats -s 2          # sessão específica
docker compose run --rm analyzer stats --all         # todas as sessões juntas
docker compose run --rm analyzer stats --order-by packets --top 10
```

### 3.5 Sem Docker Compose (docker puro)

```bash
docker build -t traffic-analyzer .
docker run --rm -it --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$(pwd)/data:/data" traffic-analyzer capture -i eth0 -t 30
```

### 3.6 Sem Docker (desenvolvimento local)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
sudo apt install libpcap0.8          # necessário só para filtros BPF (-f)
sudo .venv/bin/python -m app.main capture -i eth0 -t 30
```

### 3.8 Windows

No Windows o Docker roda dentro de uma VM Linux (WSL2). Isso cria dois cenários:

**A) Docker Desktop (cumpre o requisito "rodar em Docker").** O container captura a interface da VM do Docker, então o tráfego visível é o gerado pelos containers, não o do navegador do Windows. Para gerar tráfego que a captura enxergue, use outro container na mesma rede:

```powershell
docker compose build
docker compose run --rm analyzer interfaces
docker compose run --rm analyzer capture -i eth0 -t 60

# em outro terminal, enquanto a captura roda:
docker run --rm --network host alpine sh -c "ping -c 20 8.8.8.8; wget -qO- https://example.com > /dev/null"
```

**B) Execução nativa com Npcap (captura o tráfego real do Wi-Fi/Ethernet).** Instale o Python 3.12 e o Npcap (https://npcap.com), depois:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
python -m app.main interfaces              # use o valor da coluna "Nome"
python -m app.main capture -i "Wi-Fi" -t 60
```

A opção `-i` aceita o nome amigável (`Wi-Fi`, `Ethernet`), a descrição do adaptador ou o nome NPF (`\Device\NPF_{...}`).

### 3.7 Testes

```bash
docker compose run --rm --entrypoint pytest analyzer -v
# ou localmente: pytest -v
```

---

## 4. Referência de comandos

| Comando | Opção | Descrição |
|---|---|---|
| (global) | `--db CAMINHO` | Banco SQLite (padrão: `$DB_PATH` ou `data/traffic.db`) |
| (global) | `-v` | Logs detalhados |
| `interfaces` | | Lista interfaces disponíveis |
| `capture` | `-i, --interface` | Interface (padrão: `$INTERFACE` ou a interface padrão do sistema) |
| | `-c, --count N` | Para após N pacotes (0 = sem limite) |
| | `-t, --timeout S` | Para após S segundos |
| | `-f, --filter BPF` | Filtro BPF, ex.: `"tcp"`, `"port 443"`, `"host 10.0.0.5"` |
| | `--live-interval S` | Intervalo do painel ao vivo (0 desativa; padrão 5) |
| | `--batch-size N` | Pacotes por transação no banco (padrão 500) |
| `capture`, `stats` | `--top N` | Tamanho do ranking de IPs (padrão 5) |
| | `--order-by bytes\|packets` | Critério do ranking (padrão `bytes`) |
| `stats` | `-s ID` / `--all` | Sessão específica ou todas |
| `sessions` | | Lista sessões gravadas |

Sem `-c` e sem `-t`, a captura roda até Ctrl+C ou `docker stop`. Nos dois casos ela encerra de forma limpa: grava o último lote, fecha a sessão e imprime o relatório.

### Exemplo de saída

```
================================================================
 RESULTADO - sessão #2 (eth0)
================================================================
  Total de pacotes capturados: 2031
  Volume total:                6.4 MB

  Pacotes por protocolo
  Protocolo  Pacotes      %    Bytes
  ---------  -------  -----  -------
  TCP           1911  94.1%   6.4 MB
  UDP            120   5.9%  10.4 KB

  Top 5 IPs de ORIGEM (ordenado por bytes)
  #  Endereço IP     Pacotes     Bytes  % bytes
  -  --------------  -------  --------  -------
  1  140.82.113.3        651    5.8 MB    89.7%
  2  151.101.64.223      317  563.7 KB     8.6%
  3  192.0.2.2          1003  111.7 KB     1.7%
  4  8.8.8.8              60    6.4 KB     0.1%

  Top 5 IPs de DESTINO (ordenado por bytes)
  ...
================================================================
```

---

## 5. Banco de dados

### 5.1 Schema

```sql
CREATE TABLE capture_sessions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    interface     TEXT    NOT NULL,
    bpf_filter    TEXT,
    started_at    TEXT    NOT NULL,          -- ISO-8601 UTC
    ended_at      TEXT,                      -- NULL enquanto a captura roda
    packet_count  INTEGER NOT NULL DEFAULT 0,
    dropped_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE packets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      INTEGER NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
    captured_at     REAL    NOT NULL,        -- epoch em segundos (precisão de µs)
    src_ip          TEXT,
    dst_ip          TEXT,
    protocol        TEXT    NOT NULL,
    protocol_number INTEGER,
    ip_version      INTEGER,
    size            INTEGER NOT NULL CHECK (size >= 0)
);

CREATE INDEX idx_packets_session  ON packets(session_id);
CREATE INDEX idx_packets_protocol ON packets(session_id, protocol);
CREATE INDEX idx_packets_src      ON packets(session_id, src_ip);
CREATE INDEX idx_packets_dst      ON packets(session_id, dst_ip);
```

### 5.2 Justificativa do schema

**Uma linha por pacote.** O desafio pede o armazenamento dos pacotes capturados, não só de contadores agregados. Guardar o pacote individual permite recalcular qualquer estatística depois (por janela de tempo, por outro critério de ranking, etc.) sem precisar capturar de novo.

**Tabela `capture_sessions`.** Cada execução do `capture` vira uma sessão. Isso separa capturas de dias ou interfaces diferentes, registra o contexto (interface, filtro, início/fim) e permite gerar o relatório de uma sessão específica ou de todas juntas. O `ON DELETE CASCADE` deixa apagar uma sessão inteira com um único `DELETE`.

**Colunas de `packets`.** `src_ip`, `dst_ip`, `protocol` e `size` são os campos exigidos. Além deles: `captured_at` (timestamp do kernel, permite análises por tempo), `protocol_number` (o número IANA preserva a informação exata mesmo quando não há nome amigável) e `ip_version` (separa IPv4 de IPv6 sem precisar interpretar a string do endereço).

**IPs como `TEXT`.** Funciona igual para IPv4 e IPv6, é legível em consultas manuais e o SQLite não tem tipo nativo de endereço. A alternativa (armazenar como BLOB/inteiro) economizaria espaço, mas complicaria consultas sem ganho real neste escopo.

**Colunas que aceitam NULL.** Nem todo quadro de rede é IP (por exemplo LLDP, STP). Esses quadros são gravados com IP NULL, para que o "total de pacotes capturados" seja de fato o total. As consultas de ranking ignoram NULL.

**Índices compostos começando por `session_id`.** Todas as consultas filtram por sessão e agrupam por protocolo ou IP; índices `(session_id, coluna)` atendem exatamente esse padrão.

### 5.3 Por que SQLite

SQLite não precisa de servidor, cabe em um único arquivo montado como volume e já vem na biblioteca padrão do Python, o que mantém o projeto com uma única dependência externa (Scapy). Com `journal_mode=WAL` é possível rodar `stats` enquanto outra captura escreve. Para captura contínua em produção, com muitos sensores escrevendo em paralelo ou volumes de milhões de pacotes por hora, a evolução natural seria PostgreSQL ou um banco colunar/séries temporais (ClickHouse, TimescaleDB); como o acesso ao banco está isolado em `database.py`, essa troca não afeta o resto do código.

### 5.4 Consultas úteis

```bash
sqlite3 data/traffic.db
```

```sql
-- Tráfego por minuto em uma sessão
SELECT strftime('%H:%M', captured_at, 'unixepoch') AS minuto,
       COUNT(*) AS pacotes, SUM(size) AS bytes
FROM packets WHERE session_id = 1 GROUP BY minuto;

-- Conversas (pares origem → destino) com mais bytes
SELECT src_ip, dst_ip, protocol, COUNT(*) AS pacotes, SUM(size) AS bytes
FROM packets WHERE session_id = 1
GROUP BY src_ip, dst_ip, protocol ORDER BY bytes DESC LIMIT 10;
```

---

## 6. Decisões técnicas

**Scapy com `AsyncSniffer`.** O Scapy é a biblioteca indicada no desafio, decodifica as camadas (Ethernet, IPv4, IPv6, ARP...) automaticamente e permite montar pacotes sintéticos, o que facilita os testes. O `AsyncSniffer` roda a captura em uma thread separada, deixando a thread principal livre para tratar sinais e mostrar o painel ao vivo. A opção `store=False` evita guardar todos os pacotes na memória, já que o armazenamento é o banco.

**Callback leve + gravação em lotes.** Se cada pacote gerasse um `INSERT` com commit, a escrita em disco limitaria a taxa de captura e o kernel começaria a descartar pacotes em rajadas. O callback apenas extrai os campos e coloca o registro em uma fila; a thread `PacketWriter` grava com `executemany` em transações de até 500 pacotes ou a cada 1 segundo (o que vier primeiro). A fila é limitada (100 mil itens) para que, sob carga extrema, a aplicação descarte pacotes de forma contabilizada (`dropped_count`) em vez de esgotar a memória.

**Duas fontes de estatística.** O painel ao vivo usa contadores em memória (`LiveStats`), atualizados a cada pacote, para não consultar o banco a cada atualização. O relatório final e o comando `stats` usam SQL sobre o banco, que é a fonte da verdade e funciona para capturas antigas. Um teste automatizado garante que as duas fontes produzem exatamente o mesmo resultado.

**"Mais tráfego" = mais bytes (por padrão).** O enunciado não define se "mais tráfego" é medido em pacotes ou em volume. Optei por bytes, que reflete melhor o consumo de banda (um download gera poucos pacotes grandes; um scan gera muitos pacotes pequenos). As tabelas mostram as duas métricas e `--order-by packets` muda o critério.

**Identificação do protocolo.** Para IPv4 usa-se o campo `proto` do cabeçalho; para IPv6, o `next header`, percorrendo os cabeçalhos de extensão (Hop-by-Hop, Routing, Fragment, Destination Options) até chegar à camada de transporte. Números conhecidos viram nomes (TCP, UDP, ICMP, ICMPv6, GRE...) e os demais aparecem como `IP-<número>`. ARP é registrado com os IPs que carrega (`psrc`/`pdst`). Outros quadros aparecem como `ETHERTYPE-0x....`.

**Tamanho do pacote.** `len(pkt)` é o tamanho do quadro capturado, incluindo o cabeçalho Ethernet. É o que efetivamente trafegou na interface.

**Docker.** `network_mode: host` é necessário porque, na rede bridge padrão, o container só enxerga a própria interface virtual. Em vez de `privileged: true`, são concedidas apenas as capabilities necessárias: `NET_RAW` (abrir raw sockets) e `NET_ADMIN` (modo promíscuo). A imagem instala `libpcap`, exigida pelo Scapy para compilar filtros BPF. O banco fica em um volume (`./data`), sobrevivendo à remoção do container.

**Encerramento gracioso.** `SIGINT` (Ctrl+C) e `SIGTERM` (`docker stop`) apenas sinalizam a parada; a aplicação então para o sniffer, grava o que restou na fila, fecha a sessão e imprime o relatório. O `stop_grace_period` de 15 s no compose dá tempo para isso.

**Robustez.** Interface inexistente é validada antes de começar. Pacote malformado é ignorado sem derrubar a captura. Erros da thread de captura (por exemplo, falta de permissão) são repassados à thread principal e reportados com uma dica de correção.

---

## 7. Testes

Os testes em `tests/` usam pacotes montados com Scapy e SQLite em memória, então rodam sem rede e sem root. Eles cobrem a extração de campos para IPv4/TCP, UDP, ICMP, IPv6 com cabeçalho de extensão, protocolo desconhecido, ARP e quadros não-IP; os totais e a contagem por protocolo; o ranking por bytes versus por pacotes; o limite do top N; o isolamento entre sessões; e a equivalência entre estatísticas ao vivo e as calculadas via SQL.

---

## 8. Limitações conhecidas e solução de problemas

**Docker Desktop (Windows/macOS):** a rede "host" é a da VM do Docker. Para analisar a placa de rede real, rode em um host Linux ou execute nativamente (seção 3.8, cenário B).

**Interface `lo`:** o Linux entrega cada pacote de loopback duas vezes ao raw socket (saída e entrada), então a contagem dobra. É comportamento do kernel, igual ao do tcpdump.

**`Operation not permitted`:** faltam as capabilities. Use o `docker-compose.yml` fornecido ou adicione `--cap-add NET_RAW --cap-add NET_ADMIN`.

**`libpcap is not available. Cannot compile filter`:** acontece ao rodar fora do Docker sem libpcap instalada; instale `libpcap0.8` (Debian/Ubuntu) ou rode sem `-f`.

**Alto volume de tráfego:** o Scapy é escrito em Python e decodifica cada pacote por completo, então atende bem a dezenas de milhares de pacotes por segundo no máximo. Para enlaces de vários Gbps, a abordagem indicada seria captura em C (libpcap/AF_PACKET com mmap, ou eBPF) agregando no kernel. Pacotes descartados pela fila interna são contabilizados em `capture_sessions.dropped_count`.

**Crescimento do banco:** uma linha por pacote cresce rápido em capturas longas (aprox. 100 bytes por pacote). Use `-t`/`-c`/`-f` para delimitar, ou apague sessões antigas com `DELETE FROM capture_sessions WHERE id = ...`.
