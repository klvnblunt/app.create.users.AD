import hmac
import logging
import os
import re
import secrets
import ssl
import time
import unicodedata
from functools import wraps

from flask import (Flask, abort, jsonify, redirect, render_template, request,
                   session, url_for)
from ldap3 import MODIFY_REPLACE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("adweb")

# ----------------------------------------------------------------- configuração
LDAP_HOST = os.environ.get("LDAP_HOST", "dc01.ad.gavom.local")
LDAP_PORT = int(os.environ.get("LDAP_PORT", "636"))
BIND_USER = os.environ["LDAP_BIND_USER"]
BIND_PASS = os.environ["LDAP_BIND_PASSWORD"]
BASE_DN = os.environ.get("BASE_DN", "DC=ad,DC=gavom,DC=local")
ROOT_OU = os.environ.get("ROOT_OU", f"OU=Gavom,{BASE_DN}")
USERS_OU_NAME = os.environ.get("USERS_OU_NAME", "Users")
UPN_SUFFIX = os.environ.get("UPN_SUFFIX", "ad.gavom.local")
DEFAULT_PASSWORD = os.environ["DEFAULT_PASSWORD"]
CA_FILE = os.environ.get("LDAP_CA_FILE", "/app/ca.pem")
LDAP_VERIFY = os.environ.get("LDAP_VERIFY", "1") == "1"
MAX_LINHAS = 100

WEB_USERS = {}
for par in os.environ.get("WEB_USERS", "").split(";"):
    if ":" in par:
        u, p = par.split(":", 1)
        WEB_USERS[u.strip()] = p

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
    PERMANENT_SESSION_LIFETIME=8 * 3600,
)

PARTICULAS = {"de", "da", "do", "dos", "das", "e", "di", "du"}
LOGIN_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,19}$")


# ------------------------------------------------------------------------- LDAP
def conectar():
    if LDAP_VERIFY and os.path.exists(CA_FILE):
        tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=CA_FILE)
    else:
        if LDAP_VERIFY:
            log.warning("ca.pem não encontrado em %s; certificado NÃO validado", CA_FILE)
        tls = Tls(validate=ssl.CERT_NONE)
    server = Server(LDAP_HOST, port=LDAP_PORT, use_ssl=True, tls=tls)
    return Connection(server, user=BIND_USER, password=BIND_PASS, auto_bind=True)


def listar_unidades(conn):
    """Unidades = OUs dentro de ROOT_OU que possuem uma sub-OU 'Users'."""
    conn.search(
        ROOT_OU,
        f"(&(objectClass=organizationalUnit)(ou={escape_filter_chars(USERS_OU_NAME)}))",
        search_scope=SUBTREE,
        attributes=["ou"],
    )
    profundidade = len(ROOT_OU.split(",")) + 2
    unidades = {}
    for e in conn.entries:
        partes = e.entry_dn.split(",")
        if len(partes) == profundidade and partes[1].upper().startswith("OU="):
            unidades[partes[1][3:]] = e.entry_dn
    return dict(sorted(unidades.items()))


def login_existe(conn, login):
    conn.search(BASE_DN, f"(sAMAccountName={escape_filter_chars(login)})",
                search_scope=SUBTREE, attributes=["sAMAccountName"])
    return bool(conn.entries)


def criar_usuario(conn, nome, unidade_dn, login):
    partes = nome.split()
    dn = f"CN={escape_rdn(nome)},{unidade_dn}"
    atributos = {
        "sAMAccountName": login,
        "userPrincipalName": f"{login}@{UPN_SUFFIX}",
        "givenName": partes[0],
        "sn": " ".join(partes[1:]),
        "displayName": nome,
    }
    if not conn.add(dn, ["top", "person", "organizationalPerson", "user"], atributos):
        desc = conn.result.get("description", "")
        if desc == "entryAlreadyExists":
            return False, "Já existe um objeto com esse nome completo nesta unidade."
        if desc == "insufficientAccessRights":
            return False, "Sem permissão: a conta de serviço não pode criar usuários nesta OU."
        return False, f"Falha ao criar: {desc} {conn.result.get('message', '')}".strip()
    try:
        # senha exige LDAPS; depois habilita a conta e força a troca no 1º logon
        if not conn.extend.microsoft.modify_password(dn, DEFAULT_PASSWORD):
            raise RuntimeError(f"definir senha: {conn.result.get('description')}")
        if not conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [512])],
                                "pwdLastSet": [(MODIFY_REPLACE, [0])]}):
            raise RuntimeError(f"habilitar conta: {conn.result.get('description')}")
    except Exception as exc:  # noqa: BLE001
        conn.delete(dn)  # não deixa conta pela metade
        return False, f"Criado, mas desfeito por erro ao {exc}"
    return True, "Criado. Troca de senha obrigatória no primeiro logon."


# ------------------------------------------------------------------------ nomes
def titulo(nome):
    nome = re.sub(r"[^\w\s'.-]", "", nome or "")
    saida = []
    for i, w in enumerate(nome.split()):
        w = w.lower()
        saida.append(w if (w in PARTICULAS and i > 0) else w[:1].upper() + w[1:])
    return " ".join(saida)


def limpar(texto):
    sem_acento = unicodedata.normalize("NFKD", texto).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z.]", "", sem_acento.lower())


def candidatos_login(partes):
    primeiro, ultimo = limpar(partes[0]), limpar(partes[-1])
    lista = [f"{primeiro}.{ultimo}"]
    for meio in partes[1:-1]:
        if meio.lower() not in PARTICULAS:
            lista.append(f"{primeiro}.{limpar(meio)}")
    lista += [f"{primeiro}.{ultimo}{n}" for n in range(2, 10)]
    return [c[:20].rstrip(".") for c in lista]


# -------------------------------------------------------------------- segurança
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


def checar_csrf():
    enviado = request.headers.get("X-CSRF-Token") or request.form.get("csrf", "")
    if not hmac.compare_digest(enviado.encode(), session.get("csrf", "").encode()):
        abort(400)


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if "usuario" not in session:
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper


def api_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if "usuario" not in session:
            return jsonify(erro="Sessão expirada. Entre novamente."), 401
        checar_csrf()
        return f(*a, **kw)
    return wrapper


# ------------------------------------------------------------------------ rotas
@app.route("/login", methods=["GET", "POST"])
def login():
    erro = None
    if request.method == "POST":
        checar_csrf()
        usuario = request.form.get("usuario", "").strip()
        senha = request.form.get("senha", "")
        esperado = WEB_USERS.get(usuario)
        if esperado is not None and hmac.compare_digest(senha.encode(), esperado.encode()):
            session.clear()
            session["usuario"] = usuario
            session.permanent = True
            csrf_token()
            log.info("login ok: %s", usuario)
            return redirect(url_for("index"))
        log.warning("login falhou: %s", usuario)
        time.sleep(1)
        erro = "Usuário ou senha incorretos."
    return render_template("login.html", erro=erro, csrf=csrf_token())


@app.post("/logout")
def logout():
    checar_csrf()
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
@login_required
def index():
    unidades, erro = [], None
    try:
        conn = conectar()
        unidades = list(listar_unidades(conn).keys())
        conn.unbind()
        if not unidades:
            erro = "Nenhuma unidade com a sub-OU Users foi encontrada no AD."
    except LDAPException as exc:
        log.error("LDAP: %s", exc)
        erro = "Não foi possível conectar ao AD. Confira a rede, o certificado e a conta de serviço."
    return render_template("index.html", usuario=session["usuario"], csrf=csrf_token(),
                           unidades=unidades, upn=UPN_SUFFIX, erro=erro)


def ler_linhas():
    linhas = (request.get_json(silent=True) or {}).get("linhas")
    if not isinstance(linhas, list) or not linhas:
        abort(400)
    if len(linhas) > MAX_LINHAS:
        abort(jsonify(erro=f"Máximo de {MAX_LINHAS} usuários por vez."), 400)
    return linhas


@app.post("/api/preview")
@api_required
def api_preview():
    linhas = ler_linhas()
    try:
        conn = conectar()
        unidades = listar_unidades(conn)
        usados, saida = set(), []
        for l in linhas:
            nome, unidade = titulo(str(l.get("nome", ""))), l.get("unidade")
            item = {"nome": nome, "unidade": unidade, "login": "", "aviso": "", "erro": ""}
            partes = nome.split()
            if unidade not in unidades:
                item["erro"] = "Unidade inválida."
            elif len(partes) < 2:
                item["erro"] = "Informe nome e sobrenome."
            else:
                for i, c in enumerate(candidatos_login(partes)):
                    if c and c not in usados and not login_existe(conn, c):
                        item["login"] = c
                        if i:
                            item["aviso"] = "O login padrão já existe; sugerimos outro."
                        usados.add(c)
                        break
                else:
                    item["erro"] = "Não foi possível sugerir um login livre. Edite manualmente."
            saida.append(item)
        conn.unbind()
        return jsonify(linhas=saida)
    except LDAPException as exc:
        log.error("LDAP preview: %s", exc)
        return jsonify(erro="Não foi possível falar com o AD."), 502


@app.post("/api/criar")
@api_required
def api_criar():
    linhas = ler_linhas()
    try:
        conn = conectar()
        unidades = listar_unidades(conn)
        usados, resultados = set(), []
        for l in linhas:
            nome = titulo(str(l.get("nome", "")))
            unidade = l.get("unidade")
            login = str(l.get("login", "")).strip().lower()
            r = {"nome": nome, "unidade": unidade, "login": login, "ok": False, "msg": ""}
            if unidade not in unidades:
                r["msg"] = "Unidade inválida."
            elif len(nome.split()) < 2:
                r["msg"] = "Informe nome e sobrenome."
            elif not LOGIN_RE.match(login) or login.endswith("."):
                r["msg"] = "Login inválido (use letras, números, ponto; até 20 caracteres)."
            elif login in usados or login_existe(conn, login):
                r["msg"] = "Esse login já existe. Volte e escolha outro."
            else:
                usados.add(login)
                r["ok"], r["msg"] = criar_usuario(conn, nome, unidades[unidade], login)
                log.info("%s criou %s em %s: %s", session["usuario"], login, unidade,
                         "ok" if r["ok"] else r["msg"])
            resultados.append(r)
        conn.unbind()
        return jsonify(resultados=resultados)
    except LDAPException as exc:
        log.error("LDAP criar: %s", exc)
        return jsonify(erro="Não foi possível falar com o AD."), 502
