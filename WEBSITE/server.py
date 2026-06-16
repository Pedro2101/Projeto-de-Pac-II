#!/usr/bin/env python3
"""
NexoVault — Servidor local com HTTPS
Uso: python3 server.py [porta]
"""

import http.server
import socketserver
import socket
import ssl
import sys
import os
import subprocess
import webbrowser
from pathlib import Path

# ── Configuração ────────────────────────────────────────────
arg = sys.argv[1].strip() if len(sys.argv) > 1 else ""
PORT = int(arg) if arg.isdigit() else 8443
HOST = "0.0.0.0"
SITE_DIR = Path(__file__).parent
CERT_FILE = SITE_DIR / "cert.pem"
KEY_FILE  = SITE_DIR / "key.pem"
# ────────────────────────────────────────────────────────────

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def gerar_certificado():
    """Gera certificado auto-assinado com openssl se não existir."""
    if CERT_FILE.exists() and KEY_FILE.exists():
        print("  ✔  Certificado existente encontrado.")
        return

    print("  ⚙  A gerar certificado SSL auto-assinado...")
    local_ip = get_local_ip()

    # Ficheiro de config para incluir SANs (IP + localhost)
    san_conf = SITE_DIR / "san.cnf"
    san_conf.write_text(f"""[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = NexoVault Local

[v3_req]
subjectAltName = @alt_names

[alt_names]
IP.1 = {local_ip}
IP.2 = 127.0.0.1
DNS.1 = localhost
""")

    result = subprocess.run([
        "openssl", "req", "-x509", "-nodes",
        "-newkey", "rsa:2048",
        "-keyout", str(KEY_FILE),
        "-out",    str(CERT_FILE),
        "-days",   "365",
        "-config", str(san_conf),
        "-extensions", "v3_req"
    ], capture_output=True, text=True)

    san_conf.unlink()  # limpa ficheiro temporário

    if result.returncode != 0:
        print("  ✘  Erro ao gerar certificado:")
        print(result.stderr)
        sys.exit(1)

    print("  ✔  Certificado gerado: cert.pem + key.pem")


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(SITE_DIR), **kwargs)

    def do_GET(self):
        if self.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return
        super().do_GET()

    def log_message(self, fmt, *args):
        msg = fmt % args
        if "Bad request" in msg or "favicon.ico" in msg:
            return
        addr = self.client_address[0]
        print(f"  [{addr}]  {msg}")

    def log_error(self, fmt, *args):
        msg = fmt % args
        if any(x in msg for x in ("Broken pipe", "Bad request", "ConnectionReset")):
            return
        print(f"  [ERRO]  {msg}")


# ── Main ─────────────────────────────────────────────────────
os.chdir(SITE_DIR)

print()
print("  ╔══════════════════════════════════════════╗")
print("  ║        NexoVault — Servidor HTTPS        ║")
print("  ╚══════════════════════════════════════════╝")
print()

gerar_certificado()
print()

local_ip = get_local_ip()

with socketserver.TCPServer((HOST, PORT), Handler) as httpd:
    httpd.allow_reuse_address = True

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    print(f"  🌐  Local:    https://localhost:{PORT}")
    print(f"  🌐  Rede:     https://{local_ip}:{PORT}")
    print()
    print("  ⚠  Certificado auto-assinado — o browser vai mostrar aviso.")
    print('     Clicar em "Avançado" → "Continuar para o site" para aceitar.')
    print()
    print("  Pressiona Ctrl+C para parar o servidor.")
    print()

    try:
        webbrowser.open(f"https://localhost:{PORT}")
    except Exception:
        pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print()
        print("  Servidor parado. Até logo!")
        print()
