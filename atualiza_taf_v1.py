# -*- coding: utf-8 -*-
import os
import re
import subprocess
import glob

def replace_in_file(file_path, origem, destino):
    with open(file_path, 'r') as file:
        data = file.read()

    new_data = data.replace(origem, destino)

    with open(file_path, 'w') as file:
        file.write(new_data)

# Pergunta ao usuário o nome do environment
env_name = raw_input("Digite o nome do environment: ")

# Definindo as variáveis de origem e destino
origem_1 = "[taf]"
destino_1 = "[{0}]".format(env_name)

origem_2 = "envserver=taf,sped"
destino_2 = "envserver={0},sped".format(env_name)

origem_3 = "Environment=taf"
destino_3 = "Environment={0}".format(env_name)

origem_4 = "ENVIRONMENT=taf"
destino_4 = "Environment={0}".format(env_name)

origem_5 = "EnvServer=taf"
destino_5 = "EnvServer={0}".format(env_name)

origem_6 = "MaxQuerySize=655360"
destino_6 = "MaxQuerySize=65536"

origem_7 = "CtreeRootPath=/outsourcing/totvs/protheus_data/tss"
destino_7 = ""

origem_8 = "ctreemode=server"
destino_8 = ""

origem_9 = "CtreeRootPath=/outsourcing/totvs/protheus_data"
destino_9 = ""


# Usando o glob para encontrar os arquivos com o padrão
appserver_paths = glob.glob('/outsourcing/totvs/protheus/bin/*/appserver.ini')

# Descompactar smartclient.ini
#subprocess.call("unzip /outsourcing/totvs/protheus_data/downloads/smartclient.zip '*/smartclient.ini' -d /outsourcing/totvs/protheus_data/downloads/", #shell=True)

# Caminho completo para o arquivo smartclient.ini que foi descompactado
#smartclient_ini_path = '/outsourcing/totvs/protheus_data/downloads/smartclient/smartclient.ini'

# Substituições no arquivo smartclient.ini
#replace_in_file(smartclient_ini_path, origem_2, destino_2)

# Atualizando o arquivo smartclient.zip com o caminho correto para o arquivo
#subprocess.call(['zip', '-ur', '/outsourcing/totvs/protheus_data/downloads/smartclient.zip', smartclient_ini_path])

# Verifica se encontrou algum arquivo, caso contrário lança um erro
if not appserver_paths:
    print "Nenhum arquivo appserver.ini encontrado no caminho especificado."
else:
    # Substituições nos arquivos appserver.ini
    for path in appserver_paths:
        replace_in_file(path, origem_1, destino_1)
        replace_in_file(path, origem_2, destino_2)
        replace_in_file(path, origem_3, destino_3)
        replace_in_file(path, origem_4, destino_4)
        replace_in_file(path, origem_6, destino_6)
        replace_in_file(path, origem_7, destino_7)
        replace_in_file(path, origem_8, destino_8)
        replace_in_file(path, origem_9, destino_9)

    # Mais substituições nos arquivos appserver.ini
    for path in appserver_paths:
        replace_in_file(path, "StartSysInDB=1", "")
        replace_in_file(path, "ServerMemoryLimit=4096", "HeapLimit=4096")

    # Substituições no arquivo appserver_tss/appserver.ini
    replace_in_file('/outsourcing/totvs/protheus/bin/appserver_tss/appserver.ini', "/outsourcing/totvs/protheus_data/tsscerts/totvs_all.PEM", "/outsourcing/totvs/protheus_data/tss/certs/000001_all.pem")
    replace_in_file('/outsourcing/totvs/protheus/bin/appserver_tss/appserver.ini', "/outsourcing/totvs/protheus_data/tss/certs/totvs_key.pem", "/outsourcing/totvs/protheus_data/tss/certs/000001_key.pem")

    # Substituições no arquivo dbaccess.ini
    replace_in_file('/outsourcing/totvs/protheus/dbaccess/7891/dbaccess.ini', "MaxStringSize=10", "MaxStringSize=500\nLicenseModel=user\nLicenseLimit=4")
    replace_in_file('/outsourcing/totvs/protheus/dbaccess/7891/dbaccess.ini', "TableSpace=DATA", "TableSpace=")
    replace_in_file('/outsourcing/totvs/protheus/dbaccess/7891/dbaccess.ini', "IndexSpace=INDEX", "IndexSpace=")

    # Substituições adicionais nos arquivos appserver.ini
    for path in appserver_paths:
        replace_in_file(path, "TOPMemoMega=1", "TOPMemoMega=10")
        replace_in_file(path, "MaxStringSize=10", "MaxStringSize=500\nMaxQuerySize=65536")

    for path in appserver_paths:
        replace_in_file(path, "TOPMemoMega=2", "TOPMemoMega=10")

    for path in appserver_paths:
        replace_in_file(path, "MaxStringSize=50", "MaxStringSize=500\nMaxQuerySize=65536")

    # Substituições no arquivo appserver_tafws/appserver.ini
    replace_in_file('/outsourcing/totvs/protheus/bin/appserver_tafws/appserver.ini', "SECURITY=1", "security=0")
    replace_in_file('/outsourcing/totvs/protheus/bin/appserver_tafws/appserver.ini', origem_3, destino_3)
    replace_in_file('/outsourcing/totvs/protheus/bin/appserver_tafws/appserver.ini', origem_4, destino_4)
    replace_in_file('/outsourcing/totvs/protheus/bin/appserver_tss/appserver.ini', "SECURITY=1", "security=0")
    replace_in_file('/outsourcing/totvs/protheus/bin/appserver_tss/appserver.ini', destino_4, "Environment=sped")
    replace_in_file('/outsourcing/totvs/protheus/bin/appserver_taf/appserver.ini', origem_5, destino_5)
    replace_in_file('/outsourcing/totvs/protheus/bin/appserver_taf/appserver.ini', "LastMainProg=SIGAMDI", "LastMainProg=SIGATAF")
    replace_in_file('/outsourcing/totvs/protheus/bin/appserver_tafws/appserver.ini', "Instances=10,20", "Instances=2,2")
    
    

def get_ip_address():
    # Executa o comando ifconfig e captura a saída
    stream = os.popen('ifconfig')
    ifconfig_output = stream.read()

    # Regex para capturar o IP na linha que começa com 'inet'
    ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', ifconfig_output)
    
    if ip_match:
        return ip_match.group(1)
    else:
        raise Exception("IP address not found.")

def update_ini_file(ip):
    ini_file = '/outsourcing/totvs/protheus/bin/appserver_tss/appserver.ini'
    
    with open(ini_file, 'r') as file:
        lines = file.readlines()

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

    # Localiza a linha com [localhost:9400] e insere o novo bloco antes dela
    with open(ini_file, 'w') as file:
        for line in lines:
            if '[localhost:9400]' in line:
                file.write(''.join(new_block))  # Escreve o novo bloco
            file.write(line)  # Reescreve o restante do arquivo

def update_ini_file_ctree(ip):
    """
    Atualiza todos os arquivos appserver.ini removendo o bloco [CTREESERVER]
    com as configurações específicas.
    
    :param ip: Endereço IP a ser utilizado na identificação do bloco.
    """
    # Caminho com wildcard para localizar todos os appserver.ini
    ini_files_pattern = '/outsourcing/totvs/protheus/bin/*/appserver.ini'
    
    # Encontra todos os arquivos que correspondem ao padrão
    ini_files = glob.glob(ini_files_pattern)
    
    if not ini_files:
        print "Nenhum arquivo appserver.ini encontrado no caminho especificado."
        return
    
    # Define o bloco de texto a ser removido com o IP atual
    block_to_remove = (
        r'\[CTREESERVER\]\s*'
        r'CTServerName=FAIRCOMS@' + re.escape(ip) + r'\s*'
        r'CTUserId=ADMIN\s*'
        r'CTUserPass=ADMIN\s*'
    )
    
    # Compila a regex com flag de múltiplas linhas e case insensitive
    block_regex = re.compile(block_to_remove, re.MULTILINE | re.IGNORECASE)
    
    for ini_file in ini_files:
        try:
            with open(ini_file, 'r') as file:
                content = file.read()
            
            # Remove o bloco se existir
            new_content, num_subs = block_regex.subn('', content)
            
            if num_subs > 0:
                with open(ini_file, 'w') as file:
                    file.write(new_content)
                print "Bloco removido do arquivo: {}".format(ini_file)
            else:
                print "Bloco não encontrado no arquivo: {}".format(ini_file)
        
        except Exception as e:
            print "Erro ao processar o arquivo {}: {}".format(ini_file, str(e))

# Caminho do arquivo a ser modificado
limits_conf = "/etc/security/limits.conf"

# Conteúdo novo para substituir
novo_conteudo = [
    "protheus - nofile 65000\n",
    "protheus - core unlimited\n",
    "root - nofile 65000\n"
]

# Função para atualizar o arquivo
def atualizar_limits_conf(arquivo):
    with open(arquivo, 'r') as f:
        linhas = f.readlines()
    
    # Variável para armazenar novas linhas
    novas_linhas = []

    # Flag para identificar se "hard core 0" foi encontrado
    hard_core_0_encontrado = False

    for linha in linhas:
        # Verifica se é a linha com "hard core 0"
        if "* hard core 0" in linha:
            novas_linhas.append(linha)
            hard_core_0_encontrado = True
            continue

        # Substitui as linhas com "protheus" e "root"
        if "protheus        -       nofile  32768" in linha or "root    -       nofile  32768" in linha:
            continue  # Ignora as linhas antigas

        # Mantém as outras linhas que não são alteradas
        novas_linhas.append(linha)

    # Adiciona o novo conteúdo logo após "hard core 0"
    if hard_core_0_encontrado:
        novas_linhas.extend(novo_conteudo)
    else:
        # Adiciona "hard core 0" se não estiver presente no arquivo
        novas_linhas.append("* hard core 0\n")
        novas_linhas.extend(novo_conteudo)

    # Grava as mudanças no arquivo
    with open(arquivo, 'w') as f:
        f.writelines(novas_linhas)

if __name__ == "__main__":
    try:
        # Obtém o endereço IP
        ip_address = get_ip_address()
        print "Endereço IP obtido: {}".format(ip_address)
        
        # Atualiza o arquivo appserver_tss/appserver.ini
        update_ini_file(ip_address)
        print "Arquivo appserver_tss/appserver.ini atualizado com o IP: {}".format(ip_address)
        
        # Atualiza os arquivos appserver.ini removendo o bloco [CTREESERVER]
        update_ini_file_ctree(ip_address)
        
    except Exception as e:
        print "Processo interrompido devido a um erro: {}".format(str(e))
    
    # Executa o comando para ajustar o ulimit
    os.system("ulimit -c unlimited")
    os.system("ulimit -n 65000")
    os.system("ulimit -s 1024")
    os.system("ulimit -v unlimited")
    
    print "Comandos ulimit executados."
    
    # Verifica se o script está sendo executado como root
    if os.geteuid() != 0:
        print "Este script precisa ser executado como root."
    else:
        atualizar_limits_conf(limits_conf)
        print "Arquivo /etc/security/limits.conf atualizado com sucesso."

def adicionar_entrada_hosts(ip, dominio):
    entrada = f"{ip} {dominio}\n"
    arquivo_hosts = "/etc/hosts"

    try:
        # Lê o conteúdo atual do arquivo
        with open(arquivo_hosts, "r") as arquivo:
            linhas = arquivo.readlines()

        # Verifica se a entrada já existe
        if any(entrada.strip() in linha.strip() for linha in linhas):
            print("A entrada já existe no /etc/hosts.")
            return

        # Adiciona a nova entrada
        with open(arquivo_hosts, "a") as arquivo:
            arquivo.write(entrada)

        print("Entrada adicionada com sucesso.")
    
    except PermissionError:
        print("Permissão negada. Execute o script como root (sudo).")
    except Exception as e:
        print(f"Ocorreu um erro: {e}")

# Exemplo de uso
adicionar_entrada_hosts("187.94.63.180", "taf-prd.tss.cloudtotvs.com.br")
