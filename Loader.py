# Projeto Ciberseguranca - Temas 3 e 12
# Alunos: Jeremias Amado e Pedro Mota
# Este ficheiro e o menu principal que orquestra os bridges

import os
import sys
import socket
import re
import time  # <-- NOVO: para esperar entre verificações

# o nosso bridge de RE 
from bridge_re import pe_analise, detecta_packer, tira_strings

# ip e porta do kali do Pedro
KALI_IP = "100.99.121.111"
KALI_PORTA = "9999"

def deteta_kali_automatico():
    # tenta encontrar o bridge_scan do pedro na rede local
    
    ips_teste = ["100.99.121.111"]
    porta_teste = 9999
    
    for ip in ips_teste:
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((ip, porta_teste))
            s.send(b"ping")
            resp = s.recv(1024).decode()
            s.close()
            if resp == "pong":
                print(f"[*] Kali do Pedro detetado em {ip}:{porta_teste}")
                return ip, porta_teste
        except:
            continue
    
    print("[!] Kali do pedro nao encontrado. Algumas opcoes vao falhar.")
    return None, None

def mandar_pro_kali(comando):    
    try:
        s = socket.socket()
        s.settimeout(8)
        s.connect((KALI_IP, KALI_PORTA))
        s.send(comando.encode())
        resp = s.recv(4096).decode()
        s.close()
        return resp
    except:
        return "Erro: Kali nao respondeu. O bridge_scan.py esta a correr?"

def mandar_ficheiro_pro_kali(caminho_ficheiro):
    """
    Envia o ficheiro para o Kali e recebe uma resposta RÁPIDA.
    O Kali vai analisar em background, por isso nao esperamos pela analise completa.
    """
    try:
        # Cria a socket com timeout generoso (3 minutos)
        s = socket.socket()
        s.settimeout(180)  # 3 minutos é suficiente para receber o ficheiro
        s.connect((KALI_IP, KALI_PORTA))
        
        print("[*] Conectado ao Kali. A enviar comando...")
        
        # 1. Envia o comando ENVIAR_FICHEIRO
        s.send(b"ENVIAR_FICHEIRO")
        print("[*] Comando enviado. À espera de resposta do Kali...")
        
        # 2. Recebe o OK do Kali (para começar a enviar)
        resposta = s.recv(1024).decode()
        print(f"[*] Kali respondeu: {resposta}")
        
        if resposta != "OK":
            print("[!] O Kali não aceitou o pedido.")
            s.close()
            return "ERRO: Kali rejeitou o pedido de envio"
        
        # 3. Envia o tamanho do ficheiro
        tamanho = os.path.getsize(caminho_ficheiro)
        print(f"[*] Tamanho do ficheiro: {tamanho} bytes")
        s.send(str(tamanho).encode())
        
        # 4. Espera confirmação do tamanho
        resposta = s.recv(1024).decode()
        print(f"[*] Kali confirmou: {resposta}")
        
        if resposta != "OK":
            print("[!] O Kali rejeitou o tamanho.")
            s.close()
            return "ERRO: Kali rejeitou o tamanho do ficheiro"
        
        # 5. Envia o ficheiro em pedaços
        print("[*] A enviar ficheiro...")
        with open(caminho_ficheiro, "rb") as f:
            bytes_enviados = 0
            while True:
                dados = f.read(4096)
                if not dados:
                    break
                s.send(dados)
                bytes_enviados += len(dados)
                
                # Mostra progresso de 10 em 10%
                if tamanho > 0 and bytes_enviados % (max(tamanho // 10, 1)) == 0 and bytes_enviados < tamanho:
                    progresso = int((bytes_enviados / tamanho) * 100)
                    print(f"[*] Progresso: {progresso}%")
        
        print(f"[*] Ficheiro enviado! Total: {bytes_enviados} bytes")
        
        # 6. Envia FIM para avisar que acabou
        s.send(b"FIM")
        print("[*] FIM enviado. A aguardar resposta do Kali...")
        
        # 7. Recebe a resposta RÁPIDA (não espera pela análise completa)
        resultado = ""
        while True:
            try:
                parte = s.recv(4096).decode()
                if not parte:
                    break
                resultado += parte
                # Se a resposta tiver "ID da análise" ou "FIM_ANALISE", paramos
                if "ID da análise" in parte or "FIM_ANALISE" in parte:
                    break
            except socket.timeout:
                print("[!] Timeout à espera de mais dados do Kali")
                break
        
        s.close()
        
        if resultado == "":
            return "ERRO: Kali não enviou resposta"
        
        return resultado
        
    except socket.timeout:
        print("[!] TIMEOUT! O Kali demorou demasiado tempo.")
        return "ERRO: Timeout - Kali não respondeu a tempo"
        
    except ConnectionRefusedError:
        print("[!] Conexão recusada. O Kali está a correr?")
        return "ERRO: Kali offline - conexão recusada"
        
    except Exception as e:
        print(f"[!] Erro inesperado: {e}")
        return f"ERRO: {e}"

# NOVA FUNÇÃO: verificar o estado de uma análise no Kali
def verificar_analise_kali(id_analise):
    """
    Pergunta ao Kali se a análise com Radare2 já terminou.
    """
    try:
        s = socket.socket()
        s.settimeout(10)
        s.connect((KALI_IP, KALI_PORTA))
        
        comando = f"verificar_analise {id_analise}"
        s.send(comando.encode())
        
        resultado = s.recv(4096).decode()
        s.close()
        
        return resultado
        
    except Exception as e:
        return f"ERRO ao verificar análise: {e}"

def limpa():
    os.system('cls' if os.name == 'nt' else 'clear')

def menu():
    print("LOADER")
    print()
    print("Reverse Engineering:")
    print("  1. Analisar executavel (PE)")
    print("  2. Detetar packer")
    print("  3. Extrair strings")
    print()
    print("Network Scanning:")
    print("  4. Scan de portas (via Kali)")
    print("  5. Detetar WAF (via Kali)")
    print()
    print("  7. PIPELINE COMPLETO (RE + Scan)")
    print()
    print("  0. Sair")
    print()

def interpreta_resultados(analise, packer, strings):
    # funcao que interpreta os resultados sem regras fixas
    # devolve o que encontrou e sugestoes
    
    encontrado = {
        "ips": [],
        "portas": [],
        "palavras_sensiveis": [],
        "packers": [],
        "sugestoes": []
    }
    
    # olha para as strings
    for s in strings.get("strings", []):
        # procura por ip (qualquer coisa com 3 ou 4 pontos)
        if s.count(".") >= 3 and len(s) < 20:
            # tenta ver se parece ip
            partes = s.split(".")
            if len(partes) == 4:
                tudo_numero = True
                for p in partes:
                    if not p.isdigit():
                        tudo_numero = False
                        break
                if tudo_numero:
                    if s not in encontrado["ips"]:
                        encontrado["ips"].append(s)
        
        # ve se é porta
        if s.isdigit():
            num = int(s)
            if num > 0 and num < 65536:
                if s not in encontrado["portas"]:
                    encontrado["portas"].append(s)
        
        # procura emails (coisa com @)
        if "@" in s and "." in s and len(s) < 50:
            if s not in encontrado["palavras_sensiveis"]:
                encontrado["palavras_sensiveis"].append(s[:50])
        
        # procura URLs (coisa com http ou https)
        if "http" in s.lower() and len(s) < 100:
            if s not in encontrado["palavras_sensiveis"]:
                encontrado["palavras_sensiveis"].append(s[:50])
        
        # procura caminhos do Windows (coisa com C:\)
        if "C:\\" in s or "c:\\" in s:
            if s not in encontrado["palavras_sensiveis"]:
                encontrado["palavras_sensiveis"].append(s[:50])
        
        # ve se é palavra suspeita (qualquer coisa que nao seja numero)
        if len(s) >= 4 and len(s) <= 25:
            if not s.isdigit():
                if s not in encontrado["palavras_sensiveis"]:
                    encontrado["palavras_sensiveis"].append(s[:50])
    
    # olha para o packer
    if "upx" in packer.get("info", "").lower():
        encontrado["packers"].append("UPX")
        encontrado["sugestoes"].append("UPX detectado. Pode descomprimir com upx -d")
    if "vmprotect" in packer.get("info", "").lower():
        encontrado["packers"].append("VMProtect")
        encontrado["sugestoes"].append("VMProtect detectado. Dificil de reverter")
    if "themida" in packer.get("info", "").lower():
        encontrado["packers"].append("Themida")
        encontrado["sugestoes"].append("Themida detectado. Anti-debug ativo")
    
    return encontrado

def interpreta_scan(resultado_scan):
    # interpreta o resultado do scan sem regras fixas
    portas_encontradas = []
    
    linhas = resultado_scan.split("\n")
    for linha in linhas:
        # procura por "porta/tcp" ou "porta/udp"
        if "/tcp" in linha or "/udp" in linha:
            # tenta extrair o numero da porta
            partes = linha.split("/")
            if len(partes) >= 2:
                porta_str = partes[0].strip()
                if porta_str.isdigit():
                    portas_encontradas.append(porta_str)
    
    return portas_encontradas

def extrair_id_analise(texto):
    """
    Tenta extrair o ID da análise da resposta do Kali.
    Procura por "ID da análise: XXXXX"
    """
    linhas = texto.split("\n")
    for linha in linhas:
        if "ID da análise:" in linha:
            # Pega tudo depois de "ID da análise:"
            partes = linha.split("ID da análise:")
            if len(partes) >= 2:
                id_analise = partes[1].strip()
                return id_analise
    return None

def tema3_pipeline():
    print("REVERSE ENGINEERING")
    caminho = input("Caminho do executavel: ").strip()

    if not os.path.exists(caminho):
        print("Erro: ficheiro nao encontrado!")
        return

    print()
    print("[*] Alvo:", caminho)

    # analise pe
    print()
    print("[1/3] Analise estatica do PE...")
    analise = pe_analise(caminho)
    if "erro" in analise:
        print("Erro:", analise["erro"])
        return

    print("  Entry Point:", analise.get("entry_point"))
    print("  Seccoes:", analise.get("seccoes"))
    print("  DLLs:", analise.get("imports", []))
    print("  Tamanho:", analise.get("tamanho", 0), "bytes")

    # packer 
    print()
    print("[2/3] Detecao de packer...")
    packer = detecta_packer(caminho)
    print("  Packer:", packer.get("packer"))
    print("  Info:", packer.get("info"))

    # strings
    print()
    print("[3/3] Extrair strings...")
    strings = tira_strings(caminho)
    print("  Encontradas:", strings.get("quantidade"))
    for s in strings.get("strings", [])[:10]:
        print("    ->", s[:80])

    # interpreta os resultados
    print()
    print("[*] LOADER A INTERPRETAR RESULTADOS...")
    
    interpretado = interpreta_resultados(analise, packer, strings)
    
    print(f"[*] IPs encontrados: {interpretado['ips'] if interpretado['ips'] else 'Nenhum'}")
    print(f"[*] Portas encontradas: {interpretado['portas'] if interpretado['portas'] else 'Nenhuma'}")
    print(f"[*] Palavras sensiveis: {len(interpretado['palavras_sensiveis'])}")
    print(f"[*] Packers sugeridos: {interpretado['packers'] if interpretado['packers'] else 'Nenhum'}")
    
    for sugestao in interpretado["sugestoes"]:
        print(f"[!] Sugestao: {sugestao}")
    
    # decide o que fazer baseado no que encontrou
    print()
    print("[*] LOADER A DECIDIR PROXIMO PASSO...")
    
    if interpretado["ips"] and KALI_IP:
        ip_alvo = interpretado["ips"][0]
        print(f"[*] LOADER: Encontrei um IP: {ip_alvo}")
        print("[*] LOADER: Recomendo fazer scan a este IP.")
        resp = input("   Autoriza o scan? (s/n): ")
        
        if resp.lower() == "s":
            print()
            print("[*] A escanear...")
            resultado_scan = mandar_pro_kali(f"scan {ip_alvo}")
            print(resultado_scan[:500])
            
            with open("alvos.txt", "a") as f:
                f.write(f"\n[SCAN] {ip_alvo}\n")
                f.write(resultado_scan[:500])
            
            # interpreta o resultado do scan
            print()
            print("[*] LOADER: A interpretar resultados do scan...")
            portas_scan = interpreta_scan(resultado_scan)
            
            if portas_scan:
                print(f"[*] LOADER: Portas encontradas: {portas_scan}")
                print("[*] LOADER: Recomendo enviar malware para Kali para analise profunda.")
                resp2 = input("   Autoriza envio para Kali? (s/n): ")
                
                if resp2.lower() == "s":
                    print("[*] A enviar ficheiro...")
                    resultado_kali = mandar_ficheiro_pro_kali(caminho)
                    print(f"[Kali] {resultado_kali[:500]}")
                    
                    # Tenta extrair o ID da análise
                    id_analise = extrair_id_analise(resultado_kali)
                    if id_analise:
                        print(f"[*] ID da análise: {id_analise}")
                        print("[*] O Kali está a analisar o ficheiro em background.")
                        print("[*] Podes verificar o resultado mais tarde com: verificar_analise_kali()")
                        
                        # Guarda o ID no ficheiro de log
                        with open("alvos.txt", "a") as f:
                            f.write(f"\n[ID_ANALISE] {id_analise}\n")
                    
                    with open("alvos.txt", "a") as f:
                        f.write(f"\n[KALI_ANALISE] {caminho}\n")
                        f.write(resultado_kali[:500])
                    
                    # pergunta se quer gerar exploit
                    print()
                    print("[*] LOADER: Quer gerar exploit para as portas que encontrei?")
                    resp3 = input("   (s/n): ")
                    
                    if resp3 == "s" or resp3 == "S":
                        for porta in portas_scan:
                            print(f"[*] A gerar exploit para porta {porta}...")
                            res = mandar_pro_kali(f"gerar_exploit {ip_alvo} {porta}")
                            print(res)
                            
                            # guarda no ficheiro
                            with open("alvos.txt", "a") as f:
                                f.write(f"\n[EXPLOIT] {ip_alvo}:{porta}\n")
                                f.write(res)
            else:
                print("[*] LOADER: Nenhuma porta encontrada no scan.")
    
    else:
        if not interpretado["ips"]:
            print("[*] LOADER: Nao consegui encontrar nada util na analise local.")
            print("[*] LOADER: Vou para o Kali fazer analise profunda com Radare2...")
            print("[*] LOADER: O Kali vai analisar em background (pode demorar).")
            
            if KALI_IP:
                # manda automaticamente sem perguntar
                resultado_kali = mandar_ficheiro_pro_kali(caminho)
                print(f"\n[Kali] Resposta:\n{resultado_kali[:500]}")
                
                # Tenta extrair o ID da análise
                id_analise = extrair_id_analise(resultado_kali)
                if id_analise:
                    print(f"[*] ID da análise: {id_analise}")
                    print("[*] O Kali está a analisar o ficheiro em background.")
                    print("[*] Podes verificar o resultado mais tarde.")
                    
                    # Guarda o ID no ficheiro de log
                    with open("alvos.txt", "a") as f:
                        f.write(f"\n[ID_ANALISE] {id_analise}\n")
                    
                    # PERGUNTA: verificar agora?
                    resp = input("[*] Queres aguardar pela análise? (pode demorar) (s/n): ")
                    if resp.lower() == "s":
                        print("[*] A verificar estado...")
                        tentativas = 0
                        while tentativas < 10:  # Máximo 10 tentativas (30 segundos)
                            time.sleep(3)  # Espera 3 segundos entre verificações
                            estado = verificar_analise_kali(id_analise)
                            tentativas += 1
                            
                            if "ANALISE_CONCLUIDA" in estado:
                                print("[*] Análise concluída!")
                                print(estado[:500])
                                break
                            elif "ANALISE_PENDENTE" in estado:
                                print(f"[*] Ainda a analisar... (tentativa {tentativas}/10)")
                            elif "ANALISE_NAO_ENCONTRADA" in estado:
                                print("[!] ID não encontrado. Pode ter expirado.")
                                break
                            else:
                                print(f"[*] Estado: {estado[:100]}")
                        else:
                            print("[*] A análise ainda não terminou. Podes verificar depois.")
                
                # tenta extrair IPs e portas do resultado do Kali
                # converte o resultado em strings para interpretar
                strings_do_kali = {"strings": resultado_kali.split()}
                kali_interpretado = interpreta_resultados(analise, packer, strings_do_kali)
                
                if kali_interpretado["ips"]:
                    interpretado["ips"] = kali_interpretado["ips"]
                    print(f"[*] LOADER: Radare2 encontrou IP: {kali_interpretado['ips'][0]}")
                if kali_interpretado["portas"]:
                    interpretado["portas"] = kali_interpretado["portas"]
                    print(f"[*] LOADER: Radare2 encontrou portas: {kali_interpretado['portas']}")
                
                # se conseguiu encontrar algo, continua para o scan
                if interpretado["ips"]:
                    ip_alvo = interpretado["ips"][0]
                    print(f"\n[*] LOADER: IP alvo: {ip_alvo}")
                    print("[*] LOADER: Recomendo fazer scan a este IP.")
                    resp = input("   Autoriza o scan? (s/n): ")
                    
                    if resp.lower() == "s":
                        print()
                        print("[*] A escanear...")
                        resultado_scan = mandar_pro_kali(f"scan {ip_alvo}")
                        print(resultado_scan[:500])
                        
                        with open("alvos.txt", "a") as f:
                            f.write(f"\n[SCAN] {ip_alvo}\n")
                            f.write(resultado_scan[:500])
                        
                        print()
                        print("[*] LOADER: A interpretar resultados do scan...")
                        portas_scan = interpreta_scan(resultado_scan)
                        
                        if portas_scan:
                            print(f"[*] LOADER: Portas encontradas: {portas_scan}")
                            print("[*] LOADER: Quer gerar exploit para as portas que encontrei?")
                            resp2 = input("   (s/n): ")
                            
                            if resp2 == "s" or resp2 == "S":
                                for porta in portas_scan:
                                    print(f"[*] A gerar exploit para porta {porta}...")
                                    res = mandar_pro_kali(f"gerar_exploit {ip_alvo} {porta}")
                                    print(res)
                                    
                                    with open("alvos.txt", "a") as f:
                                        f.write(f"\n[EXPLOIT] {ip_alvo}:{porta}\n")
                                        f.write(res)
                        else:
                            print("[*] LOADER: Nenhuma porta encontrada no scan.")
            else:
                print("[*] LOADER: Kali offline. Nao e possivel continuar.")
        else:
            if not KALI_IP:
                print("[*] LOADER: Kali offline. Nao e possivel continuar.")
    
    # guarda tudo no alvos.txt (so no final)
    with open("alvos.txt", "a") as f:
        f.write(f"\n[RE_ANALISE] {caminho}\n")
        f.write(f"Packer: {packer.get('packer')}\n")
        f.write(f"Strings: {strings.get('quantidade')}\n")
        f.write(f"IPs encontrados: {interpretado['ips']}\n")
        f.write(f"Portas encontradas: {interpretado['portas']}\n")
    
    print()
    print("[+] Tema 3 concluido!")

def tema12_pipeline():
    print("NETWORK SCANNING")
    ip = input("IP ou dominio alvo: ").strip()

    if not ip:
        print("Erro: alvo invalido!")
        return

    print()
    print("[*] Alvo:", ip)

    print()
    print("[1/2] Scan de portas (via Kali)...")
    resp = mandar_pro_kali(f"scan {ip}")
    print(resp[:500])

    print()
    print("[2/2] Detecao de WAF (via Kali)...")
    resp = mandar_pro_kali(f"waf {ip}")
    print(resp[:500])

    print()
    print("SUGESTOES DE BYPASS")
    print("  -> Verificar portas abertas para servicos vulneraveis.")
    print("  -> Se WAF detectado, usar tecnicas de evasao.")
    print("  -> Testar credenciais default em servicos como SSH e FTP.")

    print()
    print("[+] Tema 12 concluido!")

def pipeline_completo():
    print("PIPELINE AUTOMATICO")

    print()
    print(">>> FASE 1: REVERSE ENGINEERING <<<")
    tema3_pipeline()

    print()
    print(">>> FASE 2: NETWORK SCANNING <<<")
    tema12_pipeline()

    print()
    print("[+] Pipeline concluido! Ver relatorio para mais detalhes.")

def main():
    
    global KALI_IP, KALI_PORTA
    
    kali_ip, kali_porta = deteta_kali_automatico()
    if kali_ip:
        KALI_IP = kali_ip
        KALI_PORTA = kali_porta
    
    while True:
        limpa()
        menu()
        op = input("> ").strip()

        if op == "1":
            tema3_pipeline()

        elif op == "2":
            print("DETECAO DE PACKER")
            c = input("Caminho do executavel: ").strip()
            if os.path.exists(c):
                p = detecta_packer(c)
                print()
                print("Packer:", p["packer"])
                print("Info:", p["info"])
            else:
                print("Erro: ficheiro nao existe!")

        elif op == "3":
            print("EXTRACAO DE STRINGS")
            c = input("Caminho do executavel: ").strip()
            if os.path.exists(c):
                s = tira_strings(c)
                print()
                print("Strings encontradas:", s["quantidade"])
                for st in s["strings"][:10]:
                    print("  ->", st[:80])
            else:
                print("Erro: ficheiro nao existe!")

        elif op == "4":
            print("SCAN DE PORTAS")
            ip = input("IP ou dominio: ").strip()
            if ip:
                resp = mandar_pro_kali(f"scan {ip}")
                print(resp[:500])
            else:
                print("Erro: IP invalido!")

        elif op == "5":
            print("DETECAO DE WAF")
            ip = input("IP ou dominio: ").strip()
            if ip:
                resp = mandar_pro_kali(f"waf {ip}")
                print(resp[:500])
            else:
                print("Erro: IP invalido!")

        elif op == "7":
            pipeline_completo()

        elif op == "0":
            print("[*] A sair...")
            break

        else:
            print("Opcao invalida!")

        input("\n[ENTER] para continuar...")

if __name__ == "__main__":
    main()
