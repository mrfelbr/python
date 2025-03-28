#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Script para atualização de arquivos de configuração e logs do ambiente Protheus.
#
# Autor: Felipe Mororo - 2025-03-27
# Descrição: Este script faz correção no deploy do produto TAF em ambientes Linux.
#
# Versão do Python requerida: Python 2.7
#
# Instruções de uso:
#  - Execute este script com privilégios de root (por exemplo, utilizando 'sudo') para que
#    todas as alterações em arquivos de sistema sejam aplicadas corretamente.
#  - Certifique-se de que o ambiente está configurado para Python 2.7, pois o script utiliza
#    a sintaxe de impressão do Python 2 (por exemplo, print "mensagem").
#  - Para executar o script:
#         sudo ./nome_do_script.py
#
# Observação:
#  - Se for necessário utilizar Python 3, adapte as chamadas de print (por exemplo, para print("mensagem"))
#    e outras possíveis incompatibilidades de sintaxe.
#

import os
import re
import subprocess
import glob
import sys

# Listas globais para armazenar os logs
success_logs = []
error_logs = []

def log_success(message):
    """Registra e exibe mensagens de sucesso em verde."""
    success_logs.append(message)
    print "\033[92m" + message + "\033[0m"

def log_error(message):
    """Registra e exibe mensagens de erro em vermelho."""
    error_logs.append(message)
    print "\033[91m" + message + "\033[0m"

def replace_in_file(file_path, origem, destino):
    """
    Substitui 'origem' por 'destino' no arquivo. Se destino for vazio,
    remove a linha inteira que contenha a string origem.
    """
    try:
        with open(file_path, 'r') as file:
            data = file.read()
    except Exception as e:
        log_error("Erro ao ler o arquivo {}: {}".format(file_path, e))
        return

    if destino == "":
        # Monta a regex para remover a linha inteira que contenha 'origem'
        pattern = r'^.*' + re.escape(origem) + r'.*\n?'
        new_data = re.sub(pattern, '', data, flags=re.MULTILINE)
    else:
        new_data = data.replace(origem, destino)

    try:
        with open(file_path, 'w') as file:
            file.write(new_data)
        log_success("Arquivo {} modificado com sucesso (origem: '{}').".format(file_path, origem))
    except Exception as e:
        log_error("Erro ao escrever no arquivo {}: {}".format(file_path, e))

# Parâmetros de substituição
origem_1 = "MaxQuerySize=655360"
destino_1 = "MaxQuerySize=65536"

origem_2 = "CtreeRootPath=/outsourcing/totvs/protheus_data/tss"
destino_2 = ""  # Com destino vazio, a linha inteira será removida

origem_3 = "ctreemode=server"
destino_3 = ""

origem_4 = "CtreeRootPath=/outsourcing/totvs/protheus_data"
destino_4 = ""

# Novo conteúdo para atualizar o limits.conf
novo_conteudo = [
    "protheus - nofile 65000\n",
    "protheus - core unlimited\n",
    "root - nofile 65000\n"
]

def get_ip_address():
    """
    Executa 'ifconfig' e extrai o primeiro endereço IP encontrado.
    """
    stream = os.popen('ifconfig')
    ifconfig_output = stream.read()
    ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', ifconfig_output)
    if ip_match:
        ip = ip_match.group(1)
        log_success("Endereço IP obtido: {}".format(ip))
        return ip
    else:
        raise Exception("IP address not found.")

def update_ini_file(ip):
    """
    Atualiza o arquivo appserver_tss/appserver.ini inserindo um novo bloco de configuração
    antes da linha que contém [localhost:9400].
    """
    ini_file = '/outsourcing/totvs/protheus/bin/appserver_tss/appserver.ini'
    try:
        with open(ini_file, 'r') as file:
            lines = file.readlines()
    except Exception as e:
        log_error("Erro ao ler o arquivo {}: {}".format(ini_file, e))
        return

    new_block = [
        '[{ip}:9400]\n'.format(ip=ip),
        'ENABLE=1\n',
        'PATH=/outsourcing/totvs/protheus_data/tss/web/ws\n',
        'ENVIRONMENT=sped\n',
        'RESPONSEJOB=JOB_WS\n',
        'INSTANCENAME=WS\n',
        'DEFAULTPAGE=wsindex.apw\n',
        '\n'
    ]

    try:
        with open(ini_file, 'w') as file:
            for line in lines:
                if '[localhost:9400]' in line:
                    file.write(''.join(new_block))
                file.write(line)
        log_success("Arquivo {} atualizado com o IP: {}.".format(ini_file, ip))
    except Exception as e:
        log_error("Erro ao atualizar o arquivo {}: {}".format(ini_file, e))

def update_ini_file_ctree(ip):
    """
    Atualiza todos os arquivos appserver.ini removendo o bloco [CTREESERVER]
    específico ao IP.
    """
    ini_files_pattern = '/outsourcing/totvs/protheus/bin/*/appserver.ini'
    ini_files = glob.glob(ini_files_pattern)
    if not ini_files:
        log_error("Nenhum arquivo appserver.ini encontrado no caminho especificado.")
        return

    block_to_remove = (
        r'\[CTREESERVER\]\s*'
        r'CTServerName=FAIRCOMS@' + re.escape(ip) + r'\s*'
        r'CTUserId=ADMIN\s*'
        r'CTUserPass=ADMIN\s*'
    )
    block_regex = re.compile(block_to_remove, re.MULTILINE | re.IGNORECASE)
    for ini_file in ini_files:
        try:
            with open(ini_file, 'r') as file:
                content = file.read()
            new_content, num_subs = block_regex.subn('', content)
            if num_subs > 0:
                with open(ini_file, 'w') as file:
                    file.write(new_content)
                log_success("Bloco removido do arquivo: {}".format(ini_file))
            else:
                log_success("Bloco não encontrado no arquivo: {}".format(ini_file))
        except Exception as e:
            log_error("Erro ao processar o arquivo {}: {}".format(ini_file, e))

def atualizar_limits_conf(arquivo):
    """
    Atualiza o arquivo /etc/security/limits.conf removendo linhas antigas e
    inserindo novas configurações logo após a linha "* hard core 0".
    """
    try:
        with open(arquivo, 'r') as f:
            linhas = f.readlines()
    except Exception as e:
        log_error("Erro ao ler o arquivo {}: {}".format(arquivo, e))
        return

    novas_linhas = []
    hard_core_0_encontrado = False
    for linha in linhas:
        if "* hard core 0" in linha:
            novas_linhas.append(linha)
            hard_core_0_encontrado = True
            continue
        if "protheus        -       nofile  32768" in linha or "root    -       nofile  32768" in linha:
            continue  # Ignora linhas antigas
        novas_linhas.append(linha)

    if hard_core_0_encontrado:
        novas_linhas.extend(novo_conteudo)
    else:
        novas_linhas.append("* hard core 0\n")
        novas_linhas.extend(novo_conteudo)

    try:
        with open(arquivo, 'w') as f:
            f.writelines(novas_linhas)
        log_success("Arquivo {} atualizado com sucesso.".format(arquivo))
    except Exception as e:
        log_error("Erro ao atualizar o arquivo {}: {}".format(arquivo, e))

def adicionar_entrada_hosts(ip, dominio):
    """
    Adiciona uma entrada no arquivo /etc/hosts no formato "IP dominio"
    se ela ainda não existir.
    """
    entrada = "{} {}\n".format(ip, dominio)
    arquivo_hosts = "/etc/hosts"

    try:
        with open(arquivo_hosts, "r") as arquivo:
            linhas = arquivo.readlines()
    except Exception as e:
        log_error("Erro ao ler o arquivo {}: {}".format(arquivo_hosts, e))
        return

    if any(entrada.strip() in linha.strip() for linha in linhas):
        log_success("A entrada já existe no /etc/hosts.")
        return

    try:
        with open(arquivo_hosts, "a") as arquivo:
            arquivo.write(entrada)
        log_success("Entrada adicionada com sucesso no arquivo {}.".format(arquivo_hosts))
    except PermissionError:
        log_error("Permissão negada. Execute o script como root (sudo).")
    except Exception as e:
        log_error("Ocorreu um erro ao atualizar {}: {}".format(arquivo_hosts, e))

def process_appserver_files():
    """
    Processa os arquivos appserver.ini aplicando todas as substituições necessárias.
    """
    appserver_paths = glob.glob('/outsourcing/totvs/protheus/bin/*/appserver.ini')
    if not appserver_paths:
        log_error("Nenhum arquivo appserver.ini encontrado no caminho especificado.")
        return

    for path in appserver_paths:
        replace_in_file(path, origem_1, destino_1)
        replace_in_file(path, origem_2, destino_2)
        replace_in_file(path, origem_3, destino_3)
        replace_in_file(path, origem_4, destino_4)

    for path in appserver_paths:
        replace_in_file(path, "StartSysInDB=1", "")
        replace_in_file(path, "ServerMemoryLimit=4096", "HeapLimit=4096")

    replace_in_file('/outsourcing/totvs/protheus/bin/appserver_tss/appserver.ini',
                    "/outsourcing/totvs/protheus_data/tsscerts/totvs_all.PEM",
                    "/outsourcing/totvs/protheus_data/tss/certs/000001_all.pem")
    replace_in_file('/outsourcing/totvs/protheus/bin/appserver_tss/appserver.ini',
                    "/outsourcing/totvs/protheus_data/tss/certs/totvs_key.pem",
                    "/outsourcing/totvs/protheus_data/tss/certs/000001_key.pem")

    replace_in_file('/outsourcing/totvs/protheus/dbaccess/7891/dbaccess.ini',
                    "MaxStringSize=10",
                    "MaxStringSize=500\nLicenseModel=user\nLicenseLimit=4")
    replace_in_file('/outsourcing/totvs/protheus/dbaccess/7891/dbaccess.ini',
                    "TableSpace=DATA", "TableSpace=")
    replace_in_file('/outsourcing/totvs/protheus/dbaccess/7891/dbaccess.ini',
                    "IndexSpace=INDEX", "IndexSpace=")

    for path in appserver_paths:
        replace_in_file(path, "TOPMemoMega=1", "TOPMemoMega=10")
        replace_in_file(path, "MaxStringSize=10", "MaxStringSize=500\nMaxQuerySize=65536")
    for path in appserver_paths:
        replace_in_file(path, "TOPMemoMega=2", "TOPMemoMega=10")
    for path in appserver_paths:
        replace_in_file(path, "MaxStringSize=50", "MaxStringSize=500\nMaxQuerySize=65536")

    replace_in_file('/outsourcing/totvs/protheus/bin/appserver_tafws/appserver.ini', "SECURITY=1", "security=0")
    replace_in_file('/outsourcing/totvs/protheus/bin/appserver_tss/appserver.ini', "SECURITY=1", "security=0")
    replace_in_file('/outsourcing/totvs/protheus/bin/appserver_tss/appserver.ini', "Environment=taf", "Environment=sped")
    replace_in_file('/outsourcing/totvs/protheus/bin/appserver_taf/appserver.ini', "LastMainProg=SIGAMDI", "LastMainProg=SIGATAF")
    replace_in_file('/outsourcing/totvs/protheus/bin/appserver_tafws/appserver.ini', "Instances=10,20", "Instances=2,2")

def adjust_ulimit():
    """
    Executa os comandos ulimit para ajustar os limites do sistema.
    """
    os.system("ulimit -c unlimited")
    os.system("ulimit -n 65000")
    os.system("ulimit -s 1024")
    os.system("ulimit -v unlimited")
    log_success("Comandos ulimit executados.")

def main():
    try:
        ip_address = get_ip_address()
    except Exception as e:
        log_error("Processo interrompido devido a um erro ao obter IP: {}".format(e))
        return

    update_ini_file(ip_address)
    update_ini_file_ctree(ip_address)
    process_appserver_files()

    limits_conf = "/etc/security/limits.conf"
    if os.geteuid() != 0:
        log_error("Este script precisa ser executado como root.")
    else:
        atualizar_limits_conf(limits_conf)

    adicionar_entrada_hosts("187.94.63.180", "taf-prd.tss.cloudtotvs.com.br")
    adjust_ulimit()

if __name__ == "__main__":
    main()

    # Exibe um resumo final dos logs
    print "\nResumo dos logs:"
    if success_logs:
        print "\033[92mSucessos:\033[0m"
        for msg in success_logs:
            print "\033[92m - " + msg + "\033[0m"
    if error_logs:
        print "\033[91mErros:\033[0m"
        for msg in error_logs:
            print "\033[91m - " + msg + "\033[0m"
