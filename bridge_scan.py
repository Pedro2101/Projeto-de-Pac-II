# Bridge de Network Scanning - Tema 12
# Corre no Kali do Pedro recebe comandos do loader.py do jeremias

import socket
import subprocess
import os
import time
import threading  # <-- NOVO: para correr coisas em background

PORTA = 9999

# Dicionário para guardar resultados de análises em background
# Isto é como um "post-it" para o Kali lembrar-se do que já analisou
analises_pendentes = {}
analises_concluidas = {}

def corre_nmap_portas(ip):
    try:
        r = subprocess.run(
            ["nmap", "-F", ip],
            capture_output=True, text=True, timeout=30
        )
        return r.stdout
    except:
        return "Erro ao correr nmap."

def corre_nmap_waf(ip):
    try:
        r = subprocess.run(
            ["nmap", "-p", "80,443", "--script", "http-waf-detect", ip],
            capture_output=True, text=True, timeout=30
        )
        return r.stdout
    except:
        return "Erro ao verificar WAF."

def descomprime_upx(caminho):
    # tenta descomprimir com upx
    try:
        resultado = subprocess.run(
            ["upx", "-d", caminho, "-o", caminho + "_descomp"],
            capture_output=True, text=True, timeout=30
        )
        if resultado.returncode == 0:
            return f"UPX descompressao concluida. Ficheiro: {caminho}_descomp"
        else:
            return f"UPX falhou: {resultado.stderr}"
    except:
        return "Erro ao executar upx"

def analisa_radare2_background(caminho, id_analise):
    """
    Esta função corre em background (numa thread separada).
    Não bloqueia o fluxo principal.
    """
    print(f"[*] Background: A analisar {caminho} com Radare2...")
    print(f"[*] ID da análise: {id_analise}")
    
    try:
        # Marca que a análise começou
        analises_pendentes[id_analise] = "A analisar..."
        
        # Corre o Radare2 (pode demorar minutos)
        r = subprocess.run(
            ["r2", "-A", "-q", "-c", "afl; q", caminho],
            capture_output=True, text=True, timeout=600  # 10 minutos para ficheiros grandes
        )
        
        # Guarda o resultado
        resultado = r.stdout[:1000]
        
        # Se o resultado for muito pequeno, tenta outra abordagem
        if len(resultado) < 50:
            # Tenta com strings
            r2_strings = subprocess.run(
                ["r2", "-q", "-c", "izz; q", caminho],
                capture_output=True, text=True, timeout=60
            )
            resultado += "\n\n[STRINGS]\n" + r2_strings.stdout[:500]
        
        # Guarda no dicionário de concluídas
        analises_concluidas[id_analise] = resultado
        
        # Remove da lista de pendentes
        if id_analise in analises_pendentes:
            del analises_pendentes[id_analise]
            
        print(f"[*] Background: Análise {id_analise} concluída!")
        
    except Exception as e:
        print(f"[!] Background: Erro na análise {id_analise}: {e}")
        analises_concluidas[id_analise] = f"ERRO na análise: {e}"
        if id_analise in analises_pendentes:
            del analises_pendentes[id_analise]

def recebe_ficheiro(conn):
    """
    Recebe o ficheiro do loader e devolve uma resposta RÁPIDA.
    A análise profunda com Radare2 vai correr em background.
    """
    try:
        # Recebe o tamanho do ficheiro
        dados = conn.recv(1024).decode()
        if not dados:
            return "ERRO: Não recebi tamanho"
            
        try:
            tamanho = int(dados.strip())
        except:
            return "ERRO: Tamanho inválido"
            
        conn.send(b"OK")
        
        # 2. Recebe o ficheiro
        caminho = "/tmp/malware_recebido.exe"
        f = open(caminho, "wb")
        
        recebido = 0
        while recebido < tamanho:
            dados = conn.recv(4096)
            if not dados:
                break
            f.write(dados)
            recebido += len(dados)
        
        f.close()
        print(f"[*] Ficheiro recebido: {recebido} bytes")
        
        # 3. Recebe o FIM
        fim = conn.recv(1024).decode()
        if fim != "FIM":
            print(f"[!] Não recebi FIM, recebi: {fim}")
        
        # 4. RESPOSTA RÁPIDA (antes da análise)
        resultado = f"Ficheiro recebido com sucesso!\n"
        resultado += f"Tamanho: {recebido} bytes\n"
        resultado += f"Guardado em: {caminho}\n"
        resultado += f"\n[!] A analisar em background com Radare2...\n"
        resultado += f"[!] O resultado estará disponível depois.\n"
        
        # 5. INICIA A ANÁLISE EM BACKGROUND
        # Gera um ID único para esta análise
        import time
        id_analise = f"analise_{int(time.time())}_{os.path.basename(caminho)}"
        
        # Cria uma thread para correr a análise
        thread = threading.Thread(
            target=analisa_radare2_background,
            args=(caminho, id_analise)
        )
        thread.daemon = True  # A thread morre se o programa principal morrer
        thread.start()
        
        # Guarda o ID da análise para referência futura
        resultado += f"\nID da análise: {id_analise}\n"
        
        return resultado
        
    except Exception as e:
        return f"ERRO ao receber ficheiro: {str(e)}"

def gera_exploit_simples(ip, porta, caminho_malware):
    nome = f"/tmp/exploit_{ip.replace('.', '_')}_{porta}.py"

    if porta == 445 or porta == "445":
        tipo = "EternalBlue"
        pay = f'b"\\\\\\\\{ip}\\\\IPC$"'
    elif porta == 22 or porta == "22":
        tipo = "SSH"
        pay = 'b"SSH-2.0-Exploit"'
    elif porta == 80 or porta == 443 or porta == "80" or porta == "443":
        tipo = "Web"
        pay = f'"GET / HTTP/1.1\\r\\nHost: {ip}\\r\\n\\r\\n".encode()'
    else:
        tipo = "Generico"
        pay = 'b"EXPLOIT_PAYLOAD"'

    codigo = f'''# Exploit gerado no Kali
# Alvo: {ip}:{porta}
# Tipo: {tipo}

import socket

s = socket.socket()
s.settimeout(5)
s.connect(("{ip}", {porta}))

payload = {pay}
s.send(payload)
resp = s.recv(1024)
print(resp[:100])
s.close()
'''

    open(nome, "w").write(codigo)
    return f"Exploit gerado: {nome}"

def processa(comando, conn=None):
    # processa comandos do loader
    
    if comando == "ping":
        return "pong"
    
    elif comando.startswith("scan"):
        ip = comando.split(" ")[1]
        return corre_nmap_portas(ip)
    
    elif comando.startswith("waf"):
        ip = comando.split(" ")[1]
        return corre_nmap_waf(ip)
    
    elif comando == "ENVIAR_FICHEIRO":
        if conn:
            # O conn.send(b"OK") já está dentro do recebe_ficheiro()
            return recebe_ficheiro(conn)
        else:
            return "ERRO: Comando ENVIAR_FICHEIRO sem conexao"
    
    elif comando.startswith("gerar_exploit"):
        # formato: gerar_exploit ip porta
        partes = comando.split(" ")
        if len(partes) >= 3:
            ip = partes[1]
            porta = partes[2]
            return gera_exploit_simples(ip, porta, "")
        else:
            return "ERRO: Uso: gerar_exploit <ip> <porta>"
    
    # NOVO: comando para verificar o estado de uma análise
    elif comando.startswith("verificar_analise"):
        partes = comando.split(" ")
        if len(partes) >= 2:
            id_analise = partes[1]
            
            # Verifica se a análise já está concluída
            if id_analise in analises_concluidas:
                return f"ANALISE_CONCLUIDA\n{analises_concluidas[id_analise]}"
            elif id_analise in analises_pendentes:
                return f"ANALISE_PENDENTE: {analises_pendentes[id_analise]}"
            else:
                return "ANALISE_NAO_ENCONTRADA"
        else:
            return "ERRO: Uso: verificar_analise <id>"
    
    else:
        return f"Comando desconhecido: {comando}"

def main():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORTA))
    s.listen(1)
    
    print("="*50)
    print("Bridge Scan - Kali do Pedro")
    print(f"A escutar na porta {PORTA}")
    print("Comandos disponiveis: scan, waf, ENVIAR_FICHEIRO, gerar_exploit, ping")
    print("NOVO: verificar_analise <id>")
    print("="*50)
    
    while True:
        conn, addr = s.accept()
        print(f"\n[*] Ligacao de {addr[0]}")
        
        comando = conn.recv(4096).decode().strip()
        print(f"[*] Comando: {comando}")
        
        resultado = processa(comando, conn)
        
        # Corta a resposta se for muito grande (para não sobrecarregar)
        if len(resultado) > 4000:
            resultado = resultado[:4000] + "\n[... TRUNCADO ...]"
            
        conn.send(resultado.encode())
        conn.close()
        
        print("[*] Resposta enviada")

if __name__ == "__main__":
    main()
