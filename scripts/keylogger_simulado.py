#!/usr/bin/env python3
"""
keylogger_simulado.py
Script educacional que simula o comportamento de um keylogger:
- NÃO captura teclas do sistema.
- Pode ler um arquivo de entradas sintéticas (simulated_input.txt) ou gerar entradas de exemplo.
- Demonstra registro em log, 'exfiltration' simulada (salva estatísticas em arquivo local)
  e funções de detecção/mitigação (análise de padrões, verificação de processos).

Objetivo: mostrar como logs são gerados, como detectar e como mitigar.
"""

import os
from pathlib import Path
from datetime import datetime
import json
import random
import time

LAB_DIR = Path("./lab_files")
SIM_INPUT = LAB_DIR / "simulated_input.txt"
LOG_FILE = LAB_DIR / "keylog_simulado.log"
DETECT_FILE = LAB_DIR / "detection_report.json"

def ensure_lab_dir():
    LAB_DIR.mkdir(parents=True, exist_ok=True)

def generate_simulated_input(n_lines=20):
    ensure_lab_dir()
    samples = [
        "senha123", "usuario:admin", "comando: ls -la", "teste de preenchimento",
        "http://exemplo.com/login", "senha_supersecreta", "123456", "entrada aleatoria"
    ]
    with SIM_INPUT.open("w", encoding="utf-8") as f:
        for _ in range(n_lines):
            line = random.choice(samples)
            f.write(line + "\n")
    print(f"[+] Arquivo de entradas sintéticas gerado em {SIM_INPUT}")

def record_simulated_keylog(from_file=True, interval=0.05):
    """
    Grava entradas simuladas no LOG_FILE.
    from_file=True -> lê SIM_INPUT (se existir) e registra cada linha, com timestamp.
    from_file=False -> gera linhas aleatórias.
    """
    ensure_lab_dir()
    with LOG_FILE.open("a", encoding="utf-8") as log:
        if from_file and SIM_INPUT.exists():
            with SIM_INPUT.open("r", encoding="utf-8") as f:
                for line in f:
                    ts = datetime.utcnow().isoformat() + "Z"
                    log.write(f"{ts} | {line.strip()}\n")
                    time.sleep(interval)
            print(f"[+] Entradas de {SIM_INPUT} registradas em {LOG_FILE}")
        else:
            for i in range(10):
                ts = datetime.utcnow().isoformat() + "Z"
                fake = f"simulated_input_{i}"
                log.write(f"{ts} | {fake}\n")
                time.sleep(interval)
            print(f"[+] Entradas sintéticas gravadas em {LOG_FILE}")

def analyze_log_for_sensitive_patterns():
    """
    Leitura do log e detecção simples de padrões sensíveis (e.g., 'senha', 'http', 'usuario').
    Produz um relatório JSON em DETECT_FILE.
    """
    ensure_lab_dir()
    findings = []
    keywords = ["senha", "password", "usuario", "user", "http://", "https://", "token", "passwd"]
    if not LOG_FILE.exists():
        print("[!] Nenhum log encontrado. Gere o log primeiro.")
        return
    with LOG_FILE.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            lower = line.lower()
            for kw in keywords:
                if kw in lower:
                    findings.append({"lineno": lineno, "line": line.strip(), "keyword": kw})
    report = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "log_file": str(LOG_FILE),
        "findings_count": len(findings),
        "findings": findings
    }
    DETECT_FILE.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[+] Relatório de detecção salvo em {DETECT_FILE} (achados: {len(findings)})")
    return report

def simulate_exfiltration_detection():
    """
    Demonstração de 'exfiltration' detectada: aqui apenas soma linhas e tamanho.
    Salva um resumo local em JSON (não envia nada).
    """
    ensure_lab_dir()
    if not LOG_FILE.exists():
        print("[!] Log não encontrado.")
        return
    size = LOG_FILE.stat().st_size
    lines = sum(1 for _ in LOG_FILE.open("r", encoding="utf-8"))
    summary = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "log_lines": lines,
        "log_size_bytes": size,
        "suspicious": lines > 5 or size > 500
    }
    summary_file = LAB_DIR / "exfil_summary.json"
    summary_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"[+] Sumário de exfiltração (simulação) salvo em {summary_file}")
    return summary

def mitigation_recommendations():
    recs = [
        "Use antivírus/EDR com análise de comportamento.",
        "Bloqueie processos desconhecidos e monitore criação de arquivos em pastas sensíveis.",
        "Restrinja privilégios: aplicações não precisam de acesso a eventos de teclado normalmente.",
        "Monitore conexões de saída inesperadas e conteinerize/execute aplicações em sandboxes quando possível.",
        "Educação: evitar inserir credenciais diretamente em formulários não verificados."
    ]
    for r in recs:
        print(f"- {r}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Simulação educacional de keylogger (modo seguro).")
    parser.add_argument("--gen-input", action="store_true", help="Gerar arquivo simulated_input.txt")
    parser.add_argument("--record", action="store_true", help="Registrar entradas simuladas no log")
    parser.add_argument("--analyze", action="store_true", help="Analisar o log em busca de padrões sensíveis")
    parser.add_argument("--exfil-summary", action="store_true", help="Gerar sumário de exfiltração (simulado)")
    parser.add_argument("--recs", action="store_true", help="Imprimir recomendações de mitigação")
    args = parser.parse_args()

    if args.gen_input:
        generate_simulated_input()
    if args.record:
        # por segurança, sempre grava no diretório controlado e não captura do sistema
        record_simulated_keylog(from_file=True)
    if args.analyze:
        analyze_log_for_sensitive_patterns()
    if args.exfil_summary:
        simulate_exfiltration_detection()
    if args.recs:
        mitigation_recommendations()

if __name__ == "__main__":
    main()
