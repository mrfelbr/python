import os
import sys

def reiniciar_servidor():
    try:
        print("Reiniciando o servidor...")
        os.system("reboot -f")  # -f força o reboot imediatamente
    except Exception as e:
        print(f"Erro ao tentar reiniciar o servidor: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Verifica se o script está sendo executado como root
    if os.geteuid() != 0:
        print("Este script precisa ser executado como root.")
        sys.exit(1)
    
    reiniciar_servidor()
