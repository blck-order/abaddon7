# c2_server.py - Servidor de Comando e Controle para Abaddon 8.0

import paho.mqtt.client as mqtt
import json
import time
import threading

# --- Configuração ---
MQTT_BROKER = "broker.hivemq.com"
MQTT_PORT = 1883

# Tópicos MQTT
COMMAND_TOPIC_BASE = "abaddon/commands"
RESULTS_TOPIC = "abaddon/results/#"  # '#' é um wildcard para receber de todos os nós

online_nodes = {} # Dicionário para rastrear nós ativos

# --- Funções Callback do MQTT ---

def on_connect(client, userdata, flags, rc):
    """Callback para quando o cliente se conecta ao broker."""
    if rc == 0:
        print("[+] Conectado com sucesso ao Broker MQTT!")
        # Se inscreve no tópico de resultados para ouvir o que os nós enviam
        client.subscribe(RESULTS_TOPIC)
        print(f"[*] Ouvindo por resultados no tópico: {RESULTS_TOPIC}")
    else:
        print(f"[!] Falha na conexão, código de retorno: {rc}")

def on_message(client, userdata, msg):
    """Callback para quando uma mensagem é recebida dos nós."""
    try:
        payload = json.loads(msg.payload.decode())
        node_id = msg.topic.split('/')[-1] # Extrai o ID do nó do tópico
        
        # Atualiza o status do nó
        if node_id not in online_nodes:
            online_nodes[node_id] = {"last_seen": time.time()}
            print(f"\n[+] Novo nó online: {node_id}")

        online_nodes[node_id]["last_seen"] = time.time()

        # Processa a mensagem recebida
        status = payload.get("status")
        vuln_data = payload.get("data")

        if status == "online":
            print(f"[*] Nó {node_id} reportou status: ONLINE")
        elif status == "scan_complete":
            target = payload.get("target")
            count = payload.get("vulnerabilities_found")
            print(f"[SUCCESS] Nó {node_id} completou o scan em '{target}'. Encontrou {count} vulnerabilidades.")
        elif payload.get("type") == "vulnerability" and vuln_data:
            print("\n------------------ VULNERABILIDADE ENCONTRADA ------------------")
            print(f"  Nó:       {node_id}")
            print(f"  URL:      {vuln_data.get('url')}")
            print(f"  Tipo:     {vuln_data.get('vuln')}")
            print(f"  Parâmetro:{vuln_data.get('param')}")
            print(f"  Payload:  {vuln_data.get('payload')}")
            print("----------------------------------------------------------------\n")
        else:
            # Imprime outras mensagens para debug
            print(f"\n[DEBUG] Mensagem recebida do nó {node_id}: {payload}")

    except Exception as e:
        print(f"\n[!] Erro ao processar mensagem de {msg.topic}: {e}")
        print(f"    Payload bruto: {msg.payload.decode()}")

# --- Funções de Controle ---

def publish_command(client, target_node, command):
    """Publica um comando para um nó específico ou para todos."""
    topic = f"{COMMAND_TOPIC_BASE}/{target_node}"
    payload = json.dumps(command)
    
    client.publish(topic, payload)
    print(f"[*] Comando enviado para o tópico '{topic}': {payload}")

def print_help():
    print("\nComandos disponíveis:")
    print("  scan <alvo> <node_id|all>  - Envia uma ordem de scan (ex: scan example.com all)")
    print("  nodes                        - Lista todos os nós online")
    print("  shutdown <node_id|all>     - Desliga um ou todos os nós")
    print("  help                         - Mostra esta ajuda")
    print("  exit                         - Fecha o servidor C2\n")

def command_loop(client):
    """Loop principal para a interface de usuário do C2."""
    time.sleep(1) # Espera a conexão se estabelecer
    print_help()
    
    while True:
        try:
            cmd_input = input("C2> ").strip()
            if not cmd_input:
                continue

            parts = cmd_input.split()
            command = parts[0].lower()

            if command == "exit":
                break
            elif command == "help":
                print_help()
            elif command == "nodes":
                print("\n--- Nós Online ---")
                if not online_nodes:
                    print("Nenhum nó online.")
                else:
                    for node, data in online_nodes.items():
                        last_seen_ago = int(time.time() - data['last_seen'])
                        print(f"  - ID: {node} (Visto por último: {last_seen_ago}s atrás)")
                print("")
            elif command == "scan":
                if len(parts) < 3:
                    print("[!] Uso: scan <alvo> <node_id|all>")
                    continue
                target_domain = parts[1]
                target_node = parts[2]
                cmd_payload = {"action": "scan", "target": target_domain}
                publish_command(client, target_node, cmd_payload)
            elif command == "shutdown":
                if len(parts) < 2:
                    print("[!] Uso: shutdown <node_id|all>")
                    continue
                target_node = parts[1]
                cmd_payload = {"action": "shutdown"}
                publish_command(client, target_node, cmd_payload)
            else:
                print(f"[!] Comando '{command}' desconhecido. Digite 'help' para ver as opções.")

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[!] Erro no loop de comando: {e}")

# --- Função Principal ---
def main():
    client = mqtt.Client(client_id="abaddon-c2-server-master")
    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(MQTT_BROKER, MQTT_PORT, 60)
    except Exception as e:
        print(f"[!] Não foi possível conectar ao broker MQTT: {e}")
        return

    # Inicia o loop de rede MQTT em uma thread separada
    client.loop_start()

    # Inicia o loop de comandos do usuário na thread principal
    command_loop(client)

    # Limpeza ao sair
    client.loop_stop()
    print("\n[*] Servidor C2 encerrado.")

if __name__ == "__main__":
    main()
