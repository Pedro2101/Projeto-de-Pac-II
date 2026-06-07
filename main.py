# main.py
# Projeto Ciberseguranca - Temas 3 e 12
# Alunos: Jeremias Amado e Pedro Mota
# Este ficheiro e o menu principal unificados com os bridges.

import os
import sys
import socket

# o nosso bridge de RE
from bridge_re import pe_analise, detecta_packer, tira_strings

# ip e porta do kali do Pedro 
KALI_IP = "192.168.1.100"
KALI_PORTA = 4444


def mandar_pro_kali(comando):
    """manda um comando para o bridge_scan.py que esta no kali."""
    try:
        s = socket.socket()
        s.settimeout(8)
        s.connect((KALI_IP, KALI_PORTA))
        s.send(comando.encode())
        # recebe a resposta
        resp = s.recv(4096).decode()
        s.close()
        return resp
    except:
        return "Erro: Kali nao respondeu. O bridge_scan.py esta a correr?"


def limpa():
    """limpa o ecra."""
    os.system('cls' if os.name == 'nt' else 'clear')


def menu():
    print("=" * 50)
    print(" PROJETO CIBER")
    print("=" * 50)
    print()
    print("Reverse Engineering:")
    print("  1. Analisar executavel (PE)")
    print("  2. Detetar packer")
    print("  3. Extrair strings suspeitas")
    print()
    print("Network Scanning:")
    print("  4. Scan de portas (via Kali)")
    print("  5. Detetar WAF (via Kali)")
    print()
    print("  7. PIPELINE COMPLETO (RE + Scan)")
    print()
    print("  0. Sair")
    print()

#corre o tema 3 completo analise pe + packer + strings.
def tema3_pipeline():
    print("\nREVERSE ENGINEERING")
    caminho = input("Caminho do executavel: ").strip()

    if not os.path.exists(caminho):
        print("Erro: ficheiro nao encontrado!")
        return

    print("\n[*] Alvo:", caminho)

    # analise pe
    print("\n[1/3] Analise estatica do PE...")
    analise = pe_analise(caminho)
    if "erro" in analise:
        print("Erro:", analise["erro"])
        return

    print("  Entry Point:", analise.get("entry_point"))
    print("  Seccoes:", analise.get("seccoes"))
    print("  DLLs:", analise.get("imports", []))
    print("  Tamanho:", analise.get("tamanho", 0), "bytes")

    # packer
    print("\n[2/3] Detecao de packer...")
    packer = detecta_packer(caminho)
    print("  Packer:", packer.get("packer"))
    print("  Info:", packer.get("info"))

    # strings
    print("\n[3/3] Strings suspeitas...")
    strings = tira_strings(caminho)
    print("  Encontradas:", strings.get("quantidade"))
    for s in strings.get("strings", [])[:5]:
        print("    ->", s[:80])

    # sugestoes
    print("\n[SUGESTOES DE BYPASS]")
    if packer.get("packer") != "Nenhum":
        print("  -> Usar unpacker para", packer.get("packer"))
    else:
        print("  -> Binario sem packer. Usar Frida para instrumentacao.")
    if strings.get("quantidade", 0) > 0:
        print("  -> Strings suspeitas encontradas. Verificar comunicacao de rede.")

    print("\n[+] Tema 3 concluido!")

#corre o tema 12 manda comandos para o kali do pedro.
def tema12_pipeline():
    
    print("\nNETWORK SCANNING")
    ip = input("IP ou dominio alvo: ").strip()

    if not ip:
        print("Erro: alvo invalido!")
        return

    print("\n[*] Alvo:", ip)

    # portas
    print("\n[1/2] Scan de portas (via Kali)...")
    resp = mandar_pro_kali(f"portas {ip}")
    print(resp[:500])

    # waf
    print("\n[2/2] Detecao de WAF (via Kali)...")
    resp = mandar_pro_kali(f"waf {ip}")
    print(resp[:500])

    # sugestoes
    print("\n[SUGESTOES DE BYPASS]")
    print("  -> Verificar portas abertas para servicos vulneraveis.")
    print("  -> Se WAF detectado, usar tecnicas de evasao.")
    print("  -> Testar credenciais default em servicos como SSH e FTP.")

    print("\n[+] bypass concluido!")


def pipeline_completo():
    """ corre os dois temas. sem perguntas no meio."""
    print("\n" + "=" * 50)
    print(" PIPELINE AUTOMATICO - TEMAS 3 + 12")
    print("=" * 50)

    print("\n>>> FASE 1: REVERSE ENGINEERING <<<")
    tema3_pipeline()

    print("\n>>> FASE 2: NETWORK SCANNING <<<")
    tema12_pipeline()

    print("\n[+] Pipeline concluido! Ver relatorio para mais detalhes.")


def main():
    """loop principal."""
    while True:
        limpa()
        menu()
        op = input("> ").strip()

        if op == "1":
            tema3_pipeline()

        elif op == "2":
            print("\n--- DETECAO DE PACKER ---")
            c = input("Caminho do executavel: ").strip()
            if os.path.exists(c):
                p = detecta_packer(c)
                print("\nPacker:", p["packer"])
                print("Info:", p["info"])
            else:
                print("Erro: ficheiro nao existe!")

        elif op == "3":
            print("\nEXTRACAO DE STRINGS")
            c = input("Caminho do executavel: ").strip()
            if os.path.exists(c):
                s = tira_strings(c)
                print("\nStrings encontradas:", s["quantidade"])
                for st in s["strings"][:10]:
                    print("  ->", st[:80])
            else:
                print("Erro: ficheiro nao existe!")

        elif op == "4":
            print("\n--- SCAN DE PORTAS ---")
            ip = input("IP ou dominio: ").strip()
            if ip:
                resp = mandar_pro_kali(f"portas {ip}")
                print(resp[:500])
            else:
                print("Erro: IP invalido!")

        elif op == "5":
            print("\n--- DETECAO DE WAF ---")
            ip = input("IP ou dominio: ").strip()
            if ip:
                resp = mandar_pro_kali(f"waf {ip}")
                print(resp[:500])
            else:
                print("Erro: IP invalido!")

        elif op == "7":
            pipeline_completo()

        elif op == "0":
            print("\n[*] A sair...")
            break

        else:
            print("Opcao invalida!")

        input("\n[ENTER] para continuar...")


if __name__ == "__main__":
    main()