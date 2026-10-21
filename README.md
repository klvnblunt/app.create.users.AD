# app.create.users.AD
# app.users.AD

Interface web para criação de usuários em um **Samba AD DC**, sem precisar acessar o terminal do servidor nem rodar `samba-tool` manualmente.

A aplicação se comunica com o controlador de domínio via **LDAPS (LDAP sobre TLS, porta 636)**, validando o certificado da CA, e cria os usuários já dentro da unidade organizacional (OU) escolhida na tela.

## Funcionalidades

- Tela de login para acesso à interface
- Formulário de criação de usuário no Active Directory
- Seleção da unidade (OU) em que o usuário será criado
- Comunicação segura com o AD via LDAPS, com validação de certificado (`ca.pem`)
- Configuração por variáveis de ambiente (`.env`)
- Execução em container com Docker / Docker Compose

## Tecnologias

- Python (`app.py`)
- HTML, CSS e JavaScript (`templates/` e `static/`)
- LDAPS para comunicação com o Samba AD
- Docker e Docker Compose

## Estrutura do projeto

```
app.users.AD/
├── static/
│   ├── app.js
│   └── style.css
├── templates/
│   ├── index.html
│   └── login.html
├── .env.example
├── app.py
├── ca.pem
├── docker-compose.yml
├── Dockerfile
├── README.md
└── requirements.txt
```

## Pré-requisitos

- Docker e Docker Compose instalados
- Um Samba AD DC com **LDAPS habilitado** (porta 636 acessível pela rede do container da aplicação)
- O certificado da CA que assina o certificado do DC (arquivo `ca.pem`)
- Uma **conta de serviço** no AD com permissão apenas para criar usuários (por exemplo, membro de *Account Operators*), em vez de usar o Administrator


## Como usar

1. Faça login na tela inicial.
2. Preencha os dados do novo usuário (nome, sobrenome, login, etc.).
3. Escolha a unidade (OU) de destino.
4. Confirme a criação. O usuário é criado no AD via LDAPS na OU selecionada.

## Segurança

- **Nunca versione o `.env`.** Ele deve estar no `.gitignore`; apenas o `.env.example` (sem valores reais) vai para o repositório.
- Use uma conta de serviço com o **mínimo de permissões** necessárias.
- O `ca.pem` é um certificado público e pode ser versionado, mas **nunca** inclua chaves privadas (`.key`) no repositório.
- Mantenha a validação do certificado ativada na conexão LDAPS e evite expor a interface fora da rede interna sem HTTPS e autenticação.

## Contribuição

Sugestões e melhorias são bem-vindas. Abra uma issue ou envie um pull request.

## Autor

**Jonas Kelvin Costa**
