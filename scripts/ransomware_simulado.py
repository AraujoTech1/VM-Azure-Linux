#!/usr/bin/env python3
"""
ransomware_simulado.py
Exemplo educativo e seguro de criptografia simétrica aplicada a arquivos de teste.
- Opera apenas dentro da pasta ./lab_files
- Gera arquivos de teste, criptografa e descriptografa usando Fernet (cryptography)
- Inclui modo --dry-run e confirmação antes de ações que alteram arquivos

USO (exemplo):
    python3 ransomware_simulado.py --setup      # cria ./lab_files e arquivos de teste
    python3 ransomware_simulado.py --encrypt    # criptografa (pede confirmação)
    python3 ransomware_simulado.py --decrypt    # descriptografa (pede confirmação)
    python3 ransomware_simulado.py --status     # mostra arquivos e status (.enc)
"""

import os
import argparse
import getpass
from pathlib import Path
from cryptography.fernet import Fernet

LAB_DIR = Path("./lab_files")
KEY_FILE = Path("./lab_files/lab_key.key")
EXT_ENC = ".enc"
TEST_PREFIX = "teste_arquivo_"
NUM_TEST_FILES = 3

def ensure_lab_dir():
    LAB_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[+] Diretório de laboratório: {LAB_DIR.resolve()}")

def generate_key(force=False):
    if KEY_FILE.exists() and not force:
        print(f"[i] Key já existe em: {KEY_FILE}")
        return KEY_FILE.read_bytes()
    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key)
    os.chmod(KEY_FILE, 0o600)
    print(f"[+] Chave gerada em: {KEY_FILE} (permissões 600)")
    return key

def create_test_files(n=NUM_TEST_FILES):
    ensure_lab_dir()
    for i in range(1, n+1):
        p = LAB_DIR / f"{TEST_PREFIX}{i}.txt"
        if p.exists():
            print(f"[=] Já existe: {p.name}")
            continue
        p.write_text(f"Conteúdo de teste {i}\nLinha adicional para simulação.\n")
        print(f"[+] Criado: {p.name}")

def list_lab_files():
    ensure_lab_dir()
    files = sorted([f for f in LAB_DIR.iterdir() if f.is_file()])
    for f in files:
        flag = " (encrypted)" if f.name.endswith(EXT_ENC) else ""
        print(f"- {f.name}{flag}")
    if not files:
        print("[!] Nenhum arquivo encontrado em ./lab_files")

def encrypt_files(dry_run=True):
    if not KEY_FILE.exists():
        print("[!] Chave não encontrada. Gerando nova chave.")
        generate_key()
    key = KEY_FILE.read_bytes()
    f = Fernet(key)
    for p in LAB_DIR.iterdir():
        if not p.is_file():
            continue
        if p.name.endswith(EXT_ENC) or p.name == KEY_FILE.name:
            continue
        target = p.with_name(p.name + EXT_ENC)
        print(f"[>] Encriptar {p.name} -> {target.name}")
        if dry_run:
            continue
        data = p.read_bytes()
        token = f.encrypt(data)
        target.write_bytes(token)
        p.unlink()
        print(f"[+] Arquivo criptografado: {target.name}")

def decrypt_files(dry_run=True):
    if not KEY_FILE.exists():
        print("[!] Key não encontrada. Não é possível descriptografar.")
        return
    key = KEY_FILE.read_bytes()
    f = Fernet(key)
    for p in LAB_DIR.iterdir():
        if not p.is_file() or not p.name.endswith(EXT_ENC):
            continue
        orig_name = p.name[:-len(EXT_ENC)]
        target = p.with_name(orig_name)
        print(f"[>] Descriptografar {p.name} -> {target.name}")
        if dry_run:
            continue
        token = p.read_bytes()
        try:
            data = f.decrypt(token)
        except Exception as e:
            print(f"[!] Falha ao descriptografar {p.name}: {e}")
            continue
        target.write_bytes(data)
        p.unlink()
        print(f"[+] Arquivo restaurado: {target.name}")

def require_confirmation(prompt="Continuar? (yes/no): "):
    resp = input(prompt).strip().lower()
    return resp in ("y", "yes")

def main():
    parser = argparse.ArgumentParser(description="Simulação educativa (ransomware) — opera apenas em ./lab_files")
    parser.add_argument("--setup", action="store_true", help="Criar pasta e arquivos de teste")
    parser.add_argument("--gen-key", action="store_true", help="Gerar chave nova (substitui)")
    parser.add_argument("--encrypt", action="store_true", help="Criptografar arquivos de teste (requer confirmação)")
    parser.add_argument("--decrypt", action="store_true", help="Descriptografar arquivos .enc (requer confirmação)")
    parser.add_argument("--status", action="store_true", help="Listar arquivos no laboratório")
    parser.add_argument("--dry-run", action="store_true", help="Executar em modo dry-run (não altera arquivos)")
    args = parser.parse_args()

    if args.setup:
        create_test_files()
        generate_key()
        print("[+] Setup concluído. Revise ./lab_files")

    if args.gen_key:
        if require_confirmation("Gerar nova chave (substituir)? (yes/no): "):
            generate_key(force=True)
        else:
            print("[i] Operação cancelada.")

    if args.status:
        list_lab_files()

    if args.encrypt:
        print("[!] ALERTA: operação de criptografia operará somente em ./lab_files")
        if args.dry_run:
            print("[i] Modo dry-run: nenhum arquivo será alterado.")
        else:
            if not require_confirmation("CONFIRMAR criptografia dos arquivos em ./lab_files? (yes/no): "):
                print("[i] Operação cancelada pelo usuário.")
                return
        encrypt_files(dry_run=args.dry_run)

    if args.decrypt:
        print("[!] ALERTA: operação de descriptografia operará somente em ./lab_files")
        if args.dry_run:
            print("[i] Modo dry-run: nenhum arquivo será alterado.")
        else:
            if not require_confirmation("CONFIRMAR descriptografia dos arquivos em ./lab_files? (yes/no): "):
                print("[i] Operação cancelada pelo usuário.")
                return
        decrypt_files(dry_run=args.dry_run)

if __name__ == "__main__":
    main()
