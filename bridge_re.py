# Bridge de Reverse Engineering - Tema 3
# Tem as funcoes que o loader.py chama para analisar executaveis

def pe_analise(caminho):
    try:
        f = open(caminho, "rb")
        dados = f.read()
        f.close()

        if dados[:2] != b'MZ':
            return {"erro": "Nao e um executavel falta o MZ"}

        pe_off = int.from_bytes(dados[0x3C:0x40], 'little')
        if dados[pe_off:pe_off+4] != b'PE\x00\x00':
            return {"erro": "Assinatura PE nao encontrada"}

        entry = int.from_bytes(dados[pe_off+16:pe_off+20], 'little')

        num_sec = int.from_bytes(dados[pe_off+6:pe_off+8], 'little')
        seccoes = []
        sec_start = pe_off + 24 + int.from_bytes(dados[pe_off+20:pe_off+22], 'little')

        for i in range(num_sec):
            off = sec_start + (i * 40)
            nome = dados[off:off+8].rstrip(b'\x00').decode('ascii', errors='ignore')
            if nome:
                seccoes.append(nome)

        texto = dados.decode('latin-1', errors='ignore').lower()
        dlls_comuns = ["kernel32", "user32", "ntdll", "advapi32", "ws2_32", "wininet", "urlmon", "shell32"]
        imports = []
        for d in dlls_comuns:
            if d in texto:
                imports.append(d + ".dll")

        return {
            "entry_point": hex(entry),
            "seccoes": seccoes,
            "imports": imports,
            "tamanho": len(dados)
        }
    except Exception as e:
        return {"erro": f"Falha ao ler ficheiro: {str(e)}"}

def detecta_packer(caminho):
    # devolve strings que parecem packers
    try:
        f = open(caminho, "rb")
        dados = f.read().decode('latin-1', errors='ignore').lower()
        f.close()
        
        # as strings que geralmente aparecem em packers
        possiveis_packers = []
        padroes = ["upx", "vmprotect", "themida", "aspack", "mpress", 
                   "pecompact", "nspack", "yoda", "telock", "pete"]
        
        for padrao in padroes:
            if padrao in dados:
                possiveis_packers.append(padrao)
        
        if possiveis_packers:
            return {
                "packer": "Possivel packer detectado", 
                "info": f"Strings encontradas: {', '.join(possiveis_packers)}."
            }
        else:
            return {"packer": "Nenhum", "info": "Nenhuma string de packer conhecida encontrada."}
    except:
        return {"packer": "Erro", "info": "Nao foi possivel ler o ficheiro."}

def tira_strings(caminho):
    # tenta sacar as strings do binario
    try:
        f = open(caminho, "rb")
        dados = f.read()[:1000000]  # so os primeiros 1MB para nao demorar
        f.close()
        
        texto = dados.decode('latin-1', errors='ignore')
        
        strings = []
        palavra = ""
        for c in texto:
            if c.isprintable() or c in '\n\r\t':
                palavra += c
            else:
                if len(palavra) >= 4:
                    strings.append(palavra.strip())
                palavra = ""
        
        if len(palavra) >= 4:
            strings.append(palavra.strip())
        
        # tira duplicados
        sem_dupes = []
        for s in strings:
            if s not in sem_dupes:
                sem_dupes.append(s)
        
        return {"strings": sem_dupes[:50], "quantidade": len(sem_dupes)}
    except:
        return {"strings": [], "quantidade": 0}