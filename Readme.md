<p align="center">
  <a href="https://skillicons.dev">
    <img src="https://skillicons.dev/icons?i=azure,linux" width="420" />
  </a>
</p>

---
### VM Ubuntu na Microsoft Azure — Ambiente de Laboratório (Ubuntu 24.04 LTS)
--
## Visão Geral

Projeto demonstrativo para criação, configuração e utilização de uma Máquina Virtual (VM) Ubuntu 24.04 LTS na Microsoft Azure, com foco em práticas educativas de administração de sistemas Linux e experimentos controlados com scripts Python para fins de estudo em cibersegurança. O objetivo é fornecer um ambiente reproduzível, seguro e documentado para testes e demonstrações.

Nota de segurança: este repositório é voltado a ambientes de laboratório. Nunca armazene credenciais, senhas ou IPs públicos sensíveis em repositórios públicos. Utilize mecanismos seguros (Azure Key Vault, variáveis de ambiente, arquivos .env em .gitignore) para dados sensíveis.

## Tecnologias

Azure — Provisionamento e gerenciamento de VMs.

Ubuntu 24.04 LTS — Sistema operacional da VM.

Python 3.x — Scripts de automação, experimentos e análises.

UFW, Apache — Ferramentas de infraestrutura e teste.

## Objetivo do Projeto

Provisionar e configurar uma VM Ubuntu 24.04 LTS no Azure.

Preparar ambiente: atualização, ferramentas essenciais, Apache e UFW.

Disponibilizar scripts em Python para estudos (simulações seguras e documentadas).

Registrar e descrever medidas de defesa e mitigação relacionadas aos experimentos.

## Boas Práticas de Segurança (obrigatório)

Executar apenas em ambientes isolados (VMs de laboratório, sub-redes privadas, snapshots).

Nunca testar código malicioso em redes de produção ou com dados de usuários reais.

Versionar somente código não sensível; credenciais em Azure Key Vault ou variáveis de ambiente.

Fazer snapshots antes dos testes e restaurar o estado após as execuções.

Documentar logs e evidências localmente (não enviar a serviços externos sem autorização).

## Como Reproduzir (passos essenciais)
1. Provisionar a VM no Azure

Criar recurso: Virtual Machine → escolher imagem Ubuntu 24.04 LTS.

Recomenda-se habilitar autenticação por chave SSH para ambientes reais; para laboratório, autenticação por senha pode ser utilizada com cautela.

Configurar Network Security Group (NSG) permitindo apenas as portas necessárias (SSH e HTTP para testes).

2. Preparar a VM

Conectar-se via SSH e executar (em ambiente de laboratório):
# Atualizar sistema
sudo apt update && sudo apt upgrade -y


# Instalar utilitários
sudo apt install -y git curl wget unzip htop net-tools ufw python3 python3-venv python3-pip apache2


# Ativar e liberar Apache
sudo systemctl enable --now apache2
sudo ufw allow 'Apache Full'


# Ativar UFW (confirmar regras previamente)
sudo ufw enable

3. Preparar ambiente Python
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt # caso haja dependências

4. Executar exemplos (apenas em laboratório)

Os scripts em /scripts são didáticos e devem ser executados somente em um ambiente controlado.

Leia atentamente os comentários e a seção de segurança em cada script antes de executar.

Conteúdo dos Scripts (resumo)

ransomware_simulado.py — demonstração de criptografia simétrica aplicada em arquivos de teste (gerados localmente), com rotina de descriptografia. Não cifra dados reais nem se propõe a dano; inclui modos "dry-run".

keylogger_simulado.py — exemplo educacional que grava entradas simuladas (ex.: texto sintético) em arquivo local e mostra como detectar e mitigar esse comportamento. Não deve capturar dados de usuários reais.

Todos os scripts incluem: comentários explicativos, modo de análise (log-only), e instruções de restauração.

## Mitigação e Detecção — Checklist

Mantenha sistemas e aplicações atualizados.

Utilize antivírus/EDR com assinaturas e detecção heurística.

Habilite firewall e restrinja portas desnecessárias.

Monitore processos e conexões de rede inesperadas.

Adote políticas de privilégio mínimo (principle of least privilege).

Treine usuários sobre engenharia social e práticas seguras. 

