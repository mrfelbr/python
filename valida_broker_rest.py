# -*- coding: utf-8 -*-
import os
import subprocess
import datetime
import zipfile
import glob
import time
import socket
import requests

WEBHOOK_URL = "https://chat.googleapis.com/v1/spaces/AAAA09vAiok/messages?key=AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI&token=Veggi3Iw9HnM7jSeAsvuvSDpzxlM-2Jo0hhuluePxd8"
LOG_FILE_PATH = "/home/cloud-user/valida_broker_rest_error.log"

def log_error(message):
    with open(LOG_FILE_PATH, 'a') as log_file:
        log_file.write("{}: {}\n".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), message))

# Função para verificar a quantidade de portas em uso
def verificar_portas():
    try:
        conta_portas = subprocess.check_output("/usr/sbin/ss -aon | wc -l", shell=True).strip()
        print("Debug: Conta_Portas saída bruta:", conta_portas)  # Adicionado para debug
        conta_portas = int(conta_portas)
        return conta_portas
    except subprocess.CalledProcessError as e:
        log_error("Erro ao executar comando de verificação de portas: {}".format(e))
        return 0

# Função para verificar se a porta 4050 está fechando telnet
def verificar_porta_4050():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect(('localhost', 4050))
        s.close()
        return True
    except socket.error:
        return False

# Função para reiniciar o serviço
def reiniciar_servico():
    stop_cmd = "/outsourcing/totvs/cloud/scripts/protheus/actions/protheus_service.py stop broker_wsrest"
    start_cmd = "/outsourcing/totvs/cloud/scripts/protheus/actions/protheus_service.py start broker_wsrest"
    
    subprocess.call(stop_cmd, shell=True)
    time.sleep(10)
    subprocess.call(start_cmd, shell=True)

# Função para fazer o backup dos logs
def backup_logs():
    log_path = "/outsourcing/totvs/protheus_data/logs"
    backup_path = "/outsourcing/totvs/protheus_data/downloads/logs_backup.zip"
    logs_to_backup = ["*console_webservice_rest*", "*console_broker_special*"]

    with zipfile.ZipFile(backup_path, 'w') as backup_zip:
        for log_pattern in logs_to_backup:
            for log_file in glob.glob(os.path.join(log_path, log_pattern)):
                backup_zip.write(log_file, os.path.basename(log_file))

# Função para registrar o log incremental
def registrar_log(conta_portas, porta_responsiva):
    log_path = "/outsourcing/totvs/protheus_data/downloads/valida_broker_rest.log"
    with open(log_path, 'a') as log_file:
        log_file.write("Data e Hora: {}\n".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        log_file.write("Quantidade de portas em uso: {}\n".format(conta_portas))
        log_file.write("Porta 4050 responsiva: {}\n".format("Sim" if porta_responsiva else "Não"))
        log_file.write("\n")
    return log_path

# Função para enviar alerta via webhook
def enviar_alerta(conta_portas, porta_responsiva):
    mensagem = """
    🚨*Alerta!*🚨
    *TFBNE8 - CUJ8WY - NAPP SOLUTIONS EMPREENDIMENTOS E PARTICIPACOES LTDA ME - Produção*
    *Topologia id:* 133061
    🔴*O serviço:* *BROKER WS REST* não esta va respondendo o telnet localhost para a porta *4050* internamente!
    ✔️ O serviço foi reiniciado e normalizado!
    *Quantidade de portas em uso:* {}
    *Porta 4050 responsiva:* {}
    💾Os backups dos logs dos serviços de *WS REST* e *BROKER REST*, foram compactados e 
    disponibilizados para download no caminho: *downloads/logs_backup.zip*
    O log do monitoramento da porta foi disponibilizado no caminho: *downloads/valida_broker_rest.log*
    """.format(conta_portas, "Sim" if porta_responsiva else "Não")
    
    payload = {"text": mensagem}
    response = requests.post(WEBHOOK_URL, json=payload)
    if response.status_code != 200:
        log_error("Erro ao enviar alerta: {}".format(response.text))

def main():
    conta_portas = verificar_portas()
    print("Quantidade de portas em uso (debug):", conta_portas)  # Adicionado para debug
    porta_responsiva = verificar_porta_4050()
    
    if not porta_responsiva:
        reiniciar_servico()
        backup_logs()
        enviar_alerta(conta_portas, porta_responsiva)
    
    registrar_log(conta_portas, porta_responsiva)

if __name__ == "__main__":
    main()

