# Como publicar no GitHub (passo a passo)

> Este arquivo é um guia para você. Depois de publicar, pode apagá-lo do repositório
> (`git rm PUBLICAR.md`) ou mantê-lo — não atrapalha.

## 0. Antes de tudo: completar o que falta

- [ ] Copiar os 4 arquivos da T1110 para `tecnicas/T1110-brute-force/` e apagar o README de lá
- [ ] Colar o `<group>` da T1110 em `rules/local_rules.xml` (ou rodar `sudo ./scripts/exportar-regras.sh` no Ubuntu)
- [ ] Colocar seu LinkedIn no final do `README.md`
- [ ] (Opcional, mas valoriza muito) prints do dashboard em cada `evidencias/`

Prints não precisam estar prontos para o primeiro push — o repositório pode crescer depois.

## 1. Criar o repositório no GitHub (navegador)

1. https://github.com/new
2. **Repository name:** `wazuh-mitre-attack-lab`
3. **Description:** `Detection engineering lab: custom Wazuh rules mapped to MITRE ATT&CK, validated against a Windows DC`
4. **Public** (é portfólio — recrutador precisa ver)
5. **NÃO** marque "Add a README", ".gitignore" nem "license" — já temos esses arquivos.
   Se marcar, o GitHub cria um commit lá que conflita com o seu.
6. *Create repository*

## 2. Configurar o Git (uma vez por máquina)

```bash
# Nome e e-mail que aparecem nos commits (use o mesmo e-mail da conta GitHub)
git config --global user.name "Lucas Alves Barreto"
git config --global user.email "seu-email@exemplo.com"

# Nome padrão da branch principal
git config --global init.defaultBranch main
```

## 3. Autenticação

O GitHub não aceita senha da conta no `git push`. A forma mais simples:

```bash
# Instalar o GitHub CLI (Ubuntu)
sudo apt install gh

# Login interativo: escolha GitHub.com → HTTPS → "Login with a web browser"
gh auth login
```

O `gh` passa a fornecer o token ao Git automaticamente.

## 4. Primeiro commit e push

Na pasta do projeto (onde está o `README.md`):

```bash
cd wazuh-mitre-attack-lab

# Transforma a pasta num repositório Git (cria a pasta oculta .git)
git init

# Os scripts precisam ser executáveis também para quem clonar
chmod +x scripts/*.sh

# Ver o que SERÁ adicionado — confira que nada sensível aparece
git status

# Adiciona tudo respeitando o .gitignore
git add .

# Revisão final do que vai no commit (q para sair)
git diff --cached --stat

# Cria o commit: uma "foto" do projeto com uma mensagem
git commit -m "Lab de detecção Wazuh + MITRE ATT&CK: T1110, T1136.002, T1098, T1059.001"

# Liga o repositório local ao remoto (troque SEU-USUARIO)
git remote add origin https://github.com/SEU-USUARIO/wazuh-mitre-attack-lab.git

# Envia e define origin/main como destino padrão dos próximos "git push"
git push -u origin main
```

Abra a aba **Actions** no GitHub: o workflow "Validar regras Wazuh" deve rodar e ficar verde.

## 5. Dia a dia (próximas técnicas)

```bash
git status                       # o que mudou
git add tecnicas/T1053.005-scheduled-task rules/local_rules.xml
git commit -m "T1053.005: regras 100140-100142 e documentação"
git push
```

Commits pequenos, um por técnica ou correção, contam a história do projeto no histórico —
quem avalia o portfólio olha isso.

## 6. Deixar o perfil apresentável

- No repositório: ⚙️ ao lado de *About* → adicionar **topics**:
  `wazuh` `siem` `mitre-attack` `detection-engineering` `blue-team` `soc` `sysmon` `devsecops`
- No seu perfil: *Customize your pins* → fixar este repositório
- No LinkedIn: post curto contando um problema real da `docs/jornada.md`
  (ex.: o 4104 que não aparecia) com o link — história concreta chama mais atenção que lista de ferramentas

## Checklist de segurança antes de cada push

```bash
# Procura padrões de segredo nos arquivos que vão subir
git grep -nIiE 'password\s*[:=]|senha\s*[:=]|BEGIN (RSA|OPENSSH) PRIVATE KEY' -- . ':!PUBLICAR.md'
```

Se aparecer algo real, **não faça push**. Se um segredo já subiu, apagar o arquivo não basta
(ele continua no histórico): troque a senha imediatamente e só depois limpe o histórico.
