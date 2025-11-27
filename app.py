import os
import time
import random
import pandas as pd
import requests
import json
import io
import re
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_apscheduler import APScheduler
from sqlalchemy import func
from datetime import datetime, timedelta, date
from werkzeug.utils import secure_filename
from functools import wraps
from cryptography.fernet import Fernet

# --- CONFIGURAÇÃO GERAL ---
app = Flask(__name__)
app.secret_key = 'chave_super_secreta_academia'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
app.config['SCHEDULER_API_ENABLED'] = True

# Configuração de Criptografia
KEY_FILE = 'secret.key'
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(Fernet.generate_key())

with open(KEY_FILE, 'rb') as key_file:
    ENCRYPTION_KEY = key_file.read()

cipher_suite = Fernet(ENCRYPTION_KEY)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, faça login para acessar o sistema."
login_manager.login_message_category = "error"

# --- FUNÇÕES AUXILIARES ---
def encrypt_token(token):
    if not token: return None
    return cipher_suite.encrypt(token.encode()).decode()

def decrypt_token(token):
    if not token: return None
    try:
        return cipher_suite.decrypt(token.encode()).decode()
    except:
        return token 

def processar_upload_excel(file_path, layout_map):
    try:
        df = pd.read_excel(file_path)
        df.columns = [str(c).strip() for c in df.columns]
        dados_padronizados = []
        
        for _, row in df.iterrows():
            item = {}
            for chave_sistema, coluna_excel in layout_map.items():
                if coluna_excel in df.columns:
                    val = row[coluna_excel]
                    item[chave_sistema] = str(val).strip() if pd.notna(val) else ""
            
            # Limpeza básica de telefone (remove espaços, traços, parenteses)
            if item.get('telefone'):
                raw_tel = re.sub(r'\D', '', item['telefone'])
                item['telefone'] = raw_tel
                dados_padronizados.append(item)
                
        return dados_padronizados
    except Exception as e:
        raise Exception(f"Erro ao ler Excel: {str(e)}")

def calcular_dias_sem_acesso(data_str):
    try:
        for fmt in ['%d/%m/%Y', '%Y-%m-%d', '%d-%m-%Y']:
            try:
                dt = datetime.strptime(str(data_str).split(' ')[0], fmt)
                return (datetime.now() - dt).days
            except: continue
        return 0 
    except: return 0

def calcular_meses_ativo(data_inicio_str, dias_ativo_str):
    try:
        if data_inicio_str:
            for fmt in ['%d/%m/%Y', '%Y-%m-%d', '%d-%m-%Y']:
                try:
                    dt = datetime.strptime(str(data_inicio_str).split(' ')[0], fmt)
                    dias = (datetime.now() - dt).days
                    return int(dias / 30)
                except: continue
        if dias_ativo_str:
            return int(float(dias_ativo_str) / 30)
        return 0
    except: return 0

# --- MODELOS ---
class Usuario(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    nivel_acesso = db.Column(db.String(20), nullable=False)
    unidade = db.Column(db.String(50), nullable=True)
    ativo = db.Column(db.Boolean, default=True)
    def set_password(self, password): self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    def check_password(self, password): return bcrypt.check_password_hash(self.password_hash, password)

class Unidade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    config_api = db.relationship('ConfigAPI', backref='unidade_ref', uselist=False, lazy=True, cascade="all, delete-orphan")
    gerentes = db.relationship('Gerente', backref='unidade_ref', lazy=True, cascade="all, delete-orphan")

class ConfigAPI(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    unidade_id = db.Column(db.Integer, db.ForeignKey('unidade.id'), nullable=True, unique=True)
    api_host = db.Column(db.String(200), nullable=False)
    instance_key = db.Column(db.String(100), nullable=False)
    bearer_token = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(50), default="Desconectado")

class Gerente(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    unidade_id = db.Column(db.Integer, db.ForeignKey('unidade.id'), nullable=False)

class Template(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    tipo = db.Column(db.String(50), nullable=False)
    conteudo = db.Column(db.Text, nullable=False)
    variaveis = db.Column(db.Text)
    modulo = db.Column(db.String(20))
    regras = db.Column(db.Text)

class LayoutImportacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    mapeamento_json = db.Column(db.Text, nullable=False)

class LogEnvios(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    telefone = db.Column(db.String(20))
    nome_cliente = db.Column(db.String(200))
    unidade = db.Column(db.String(50))
    modulo = db.Column(db.String(20))
    template = db.Column(db.String(100))
    message_id = db.Column(db.String(100))
    data_envio = db.Column(db.DateTime, default=datetime.now)
    status_entrega = db.Column(db.String(20))
    status_leitura = db.Column(db.String(20))

class HistoricoCobranca(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    telefone = db.Column(db.String(20), nullable=False)
    data_envio = db.Column(db.DateTime, default=datetime.now)
    proxima_cobranca_permitida = db.Column(db.Date)
    template_usado = db.Column(db.String(100))

class RespostaAutomatica(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    palavras_chave = db.Column(db.Text, nullable=False)
    resposta = db.Column(db.Text, nullable=False)
    ativo = db.Column(db.Boolean, default=True)

# --- INTEGRAÇÃO MEGA API (CORRIGIDA PARA FORMATAR TELEFONE) ---
class MegaAPI:
    def __init__(self, host, token, instance_key):
        host = host.strip().rstrip('/')
        if not host.startswith("http"): host = f"https://{host}"
        self.host = host
        self.instance_key = instance_key
        self.headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

    def verificar_status(self):
        """Verifica se a instância está conectada e acessível"""
        try:
            url = f"{self.host}/rest/instance/{self.instance_key}"
            resp = requests.get(url, headers=self.headers, timeout=10)
            return resp.json()
        except Exception as e: return {"error": True, "message": str(e)}

    def _format_number(self, to):
        # Garante que o número tenha o sufixo correto exigido pela Mega API (Pág 40 do PDF)
        to = str(to).strip()
        if "@" in to: return to # Já formatado (ex: grupo)
        return f"{to}@s.whatsapp.net"

    def _post(self, endpoint, payload):
        time.sleep(random.uniform(3, 5))
        try:
            url = f"{self.host}/rest/sendMessage/{self.instance_key}/{endpoint}"
            resp = requests.post(url, json=payload, headers=self.headers, timeout=15)
            return resp.json()
        except Exception as e: return {"error": True, "message": str(e)}

    def enviar_mensagem_template(self, to, template_conteudo_json, dados_replace=None):
        try:
            # Formata o telefone aqui
            to_formatted = self._format_number(to)
            
            content = json.loads(template_conteudo_json) if isinstance(template_conteudo_json, str) else template_conteudo_json
            
            if dados_replace:
                def replace_vars(obj):
                    if isinstance(obj, str):
                        for k, v in dados_replace.items():
                            tag = f"{{{k}}}"
                            obj = obj.replace(tag, str(v))
                        return obj
                    elif isinstance(obj, dict): return {k: replace_vars(v) for k, v in obj.items()}
                    elif isinstance(obj, list): return [replace_vars(i) for i in obj]
                    return obj
                content = replace_vars(content)

            msg_type = content.get('type')
            if msg_type == 'text':
                return self._post("text", {"messageData": {"to": to_formatted, "text": content.get('content')}})
            elif msg_type == 'media':
                return self._post("mediaUrl", {
                    "messageData": {
                        "to": to_formatted, "url": content.get('url'), 
                        "type": content.get('mediaType', 'image'), 
                        "caption": content.get('caption', ''),
                        "mimeType": content.get('mimeType', '')
                    }
                })
            elif msg_type == 'button':
                return self._post("buttonMessage", {
                    "messageData": {
                        "to": to_formatted, "title": content.get('title'), 
                        "text": content.get('text'), 
                        "footer": content.get('footer'), 
                        "buttons": content.get('buttons')
                    }
                })
            elif msg_type == 'list':
                return self._post("listMessage", {
                    "messageData": {
                        "to": to_formatted, "buttonText": content.get('buttonText'), 
                        "text": content.get('text'), 
                        "title": content.get('title'), 
                        "description": content.get('description'), 
                        "sections": content.get('sections'), 
                        "listType": 0
                    }
                })
            elif msg_type == 'contact':
                return self._post("contactMessage", {"messageData": {"to": to_formatted, "vcard": content.get('vcard')}})
            elif msg_type == 'location':
                return self._post("locationMessage", {
                    "messageData": {
                        "to": to_formatted, "latitude": content.get('latitude'), 
                        "longitude": content.get('longitude'), 
                        "name": content.get('name'), 
                        "address": content.get('address')
                    }
                })
            return {"error": True, "message": "Tipo desconhecido"}
        except Exception as e: return {"error": True, "message": str(e)}

def get_api_credentials(unidade_id):
    config = ConfigAPI.query.filter_by(unidade_id=unidade_id).first()
    if not config: config = ConfigAPI.query.filter_by(unidade_id=None).first()
    return config

# --- ROTAS ---
@login_manager.user_loader
def load_user(user_id): return Usuario.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.nivel_acesso != 'admin':
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = Usuario.query.filter_by(username=request.form.get('username')).first()
        if user and user.check_password(request.form.get('password')):
            login_user(user)
            return redirect(url_for('index'))
        flash('Credenciais inválidas', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout(): logout_user(); return redirect(url_for('login'))

@app.route('/')
@login_required
def index(): return render_template('index.html', total_enviadas=LogEnvios.query.count())

@app.route('/boas-vindas', methods=['GET', 'POST'])
@login_required
def boas_vindas():
    layouts = LayoutImportacao.query.all()
    templates = Template.query.filter_by(modulo='geral').all()
    preview = []
    lid, tid = None, None
    
    if request.method == 'POST':
        if 'file' in request.files:
            file = request.files['file']
            lid = request.form.get('layout_id')
            tid = request.form.get('template_id')
            if file and lid and tid:
                layout = LayoutImportacao.query.get(lid)
                template = Template.query.get(tid)
                path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
                file.save(path)
                try:
                    map_dict = json.loads(layout.mapeamento_json)
                    dados = processar_upload_excel(path, map_dict)
                    tpl_json = json.loads(template.conteudo)
                    msg_base = tpl_json.get('content', tpl_json.get('text', '[Template Complexo]'))
                    
                    for d in dados:
                        uid = None
                        unid_nome = d.get('unidade', '').strip()
                        if unid_nome:
                            u_db = Unidade.query.filter(Unidade.nome.ilike(f"%{unid_nome}%")).first()
                            uid = u_db.id if u_db else None
                        msg_prev = msg_base
                        for k, v in d.items(): msg_prev = msg_prev.replace(f"{{{k.upper()}}}", str(v))
                        preview.append({'dados': d, 'status': 'Pronto', 'unidade_id': uid, 'template_id': template.id, 'unidade_nome': unid_nome, 'msg_preview': msg_prev, 'nome': d.get('aluno')})
                except Exception as e: flash(f"Erro: {e}", 'error')
        elif 'confirmar_envio' in request.form:
            dados = request.form.getlist('dados_envio')
            sucesso = 0
            for item in dados:
                try:
                    d = json.loads(item.replace("'", '"'))
                    conf = get_api_credentials(d['unidade_id'])
                    if conf:
                        token = decrypt_token(conf.bearer_token)
                        api = MegaAPI(conf.api_host, token, conf.instance_key)
                        tpl = Template.query.get(d['template_id'])
                        replace = {k.upper(): v for k, v in d['dados'].items()}
                        resp = api.enviar_mensagem_template(d['dados']['telefone'], tpl.conteudo, replace)
                        if not resp.get('error'):
                            sucesso += 1
                            db.session.add(LogEnvios(telefone=d['dados']['telefone'], unidade=d['dados'].get('unidade'), modulo='boas_vindas', message_id=resp.get('key', {}).get('id'), status_entrega='PENDING'))
                except: pass
            db.session.commit()
            flash(f'{sucesso} enviadas.', 'success')
            return redirect(url_for('boas_vindas'))
    return render_template('boas_vindas.html', layouts=layouts, templates=templates, preview=preview, layout_selecionado=int(lid) if lid else None, template_selecionado=int(tid) if tid else None)

@app.route('/cobranca', methods=['GET', 'POST'])
@login_required
def cobranca():
    layouts = LayoutImportacao.query.all()
    templates_cobranca = Template.query.filter(Template.regras != None).all()
    preview = []
    lid = None

    if request.method == 'POST':
        if 'file' in request.files:
            file = request.files['file']
            lid = request.form.get('layout_id')
            if file and lid:
                layout = LayoutImportacao.query.get(lid)
                path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
                file.save(path)
                try:
                    map_dict = json.loads(layout.mapeamento_json)
                    dados = processar_upload_excel(path, map_dict)
                    for d in dados:
                        dias_sem_acesso = calcular_dias_sem_acesso(d.get('data_hora_ultimo_acesso', ''))
                        meses_ativo = calcular_meses_ativo(d.get('inicio_plano'), d.get('tempo_ativo'))
                        debitos = int(float(d.get('debitos', 0))) if d.get('debitos') else 0
                        valor = float(d.get('valor', 0)) if d.get('valor') else 0.0
                        d['dias_sem_acesso'] = dias_sem_acesso
                        d['meses_ativo'] = meses_ativo

                        template_match = None
                        status = "Sem Regra"
                        
                        for tpl in templates_cobranca:
                            r = json.loads(tpl.regras)
                            check_fin = (r.get('min_debitos', 0) <= debitos <= r.get('max_debitos', 999) and r.get('min_dias', 0) <= dias_sem_acesso <= r.get('max_dias', 999) and r.get('min_valor', 0) <= valor)
                            if not check_fin: continue
                            if r.get('unidade_filtro') and r['unidade_filtro'] != 'Todas':
                                if r['unidade_filtro'].lower().strip() != d.get('unidade', '').lower().strip(): continue
                            if r.get('plano_filtro') and r['plano_filtro'] != 'Todos':
                                if r['plano_filtro'].lower() not in d.get('plano', '').lower(): continue
                            if r.get('min_meses_ativo') and int(r['min_meses_ativo']) > 0:
                                if meses_ativo < int(r['min_meses_ativo']): continue
                            template_match = tpl
                            break
                        
                        if template_match:
                            last_cob = HistoricoCobranca.query.filter_by(telefone=d['telefone']).order_by(HistoricoCobranca.data_envio.desc()).first()
                            if last_cob and last_cob.proxima_cobranca_permitida and last_cob.proxima_cobranca_permitida > date.today():
                                status = f"Cooldown (até {last_cob.proxima_cobranca_permitida.strftime('%d/%m')})"
                                template_match = None
                            else: status = "Pronto"

                        msg_prev = ""
                        uid = None
                        unid_nome = d.get('unidade', '').strip()
                        if unid_nome:
                            u_db = Unidade.query.filter(Unidade.nome.ilike(f"%{unid_nome}%")).first()
                            uid = u_db.id if u_db else None

                        if template_match:
                            tpl_json = json.loads(template_match.conteudo)
                            msg_prev = tpl_json.get('content', tpl_json.get('text', ''))
                            for k, v in d.items(): msg_prev = msg_prev.replace(f"{{{k.upper()}}}", str(v))
                        
                        if template_match or "Cooldown" in status:
                            preview.append({'dados': d, 'status': status, 'unidade_id': uid, 'template_id': template_match.id if template_match else None, 'template_nome': template_match.nome if template_match else "-", 'msg_preview': msg_prev, 'nome': d.get('aluno'), 'detalhes': f"{debitos} débitos | {dias_sem_acesso}d s/ acesso | {meses_ativo}m ativo"})
                except Exception as e: flash(f"Erro: {e}", 'error')

        elif 'confirmar_envio' in request.form:
            dados = request.form.getlist('dados_envio')
            sucesso = 0
            for item in dados:
                try:
                    d = json.loads(item.replace("'", '"'))
                    if d['status'] != "Pronto": continue
                    conf = get_api_credentials(d['unidade_id'])
                    if conf:
                        token = decrypt_token(conf.bearer_token)
                        api = MegaAPI(conf.api_host, token, conf.instance_key)
                        tpl = Template.query.get(d['template_id'])
                        regras = json.loads(tpl.regras)
                        replace = {k.upper(): v for k, v in d['dados'].items()}
                        resp = api.enviar_mensagem_template(d['dados']['telefone'], tpl.conteudo, replace)
                        if not resp.get('error'):
                            sucesso += 1
                            db.session.add(LogEnvios(telefone=d['dados']['telefone'], unidade=d['dados'].get('unidade'), modulo='cobranca', message_id=resp.get('key', {}).get('id'), status_entrega='PENDING'))
                            prox = date.today() + timedelta(days=int(regras.get('cooldown', 7)))
                            db.session.add(HistoricoCobranca(telefone=d['dados']['telefone'], proxima_cobranca_permitida=prox, template_usado=tpl.nome))
                except: pass
            db.session.commit()
            flash(f'{sucesso} cobranças enviadas.', 'success')
            return redirect(url_for('cobranca'))
    return render_template('cobranca.html', layouts=layouts, preview=preview, layout_selecionado=int(lid) if lid else None)

@app.route('/config-regras/<int:id>', methods=['GET', 'POST'])
@login_required
def config_regras(id):
    tpl = Template.query.get_or_404(id)
    if request.method == 'POST':
        regras = {
            "min_debitos": int(request.form.get('min_debitos', 0)),
            "max_debitos": int(request.form.get('max_debitos', 999)),
            "min_dias": int(request.form.get('min_dias', 0)),
            "max_dias": int(request.form.get('max_dias', 999)),
            "min_valor": float(request.form.get('min_valor', 0)),
            "cooldown": int(request.form.get('cooldown', 7)),
            "unidade_filtro": request.form.get('unidade_filtro'),
            "plano_filtro": request.form.get('plano_filtro'),
            "min_meses_ativo": int(request.form.get('min_meses_ativo', 0))
        }
        tpl.regras = json.dumps(regras)
        tpl.modulo = 'cobranca'
        db.session.commit()
        flash('Regras atualizadas!', 'success')
        return redirect(url_for('templates'))
    regras = json.loads(tpl.regras) if tpl.regras else {}
    unidades = Unidade.query.all()
    return render_template('config_regras.html', tpl=tpl, regras=regras, unidades=unidades)

@app.route('/layouts', methods=['GET', 'POST'])
@login_required
def layouts():
    if request.method == 'POST':
        mapeamento = {}
        for key, val in request.form.items():
            if key.startswith('map_') and val.strip(): mapeamento[key.replace('map_', '')] = val.strip()
        db.session.add(LayoutImportacao(nome=request.form['nome'], mapeamento_json=json.dumps(mapeamento)))
        db.session.commit()
        return redirect(url_for('layouts'))
    layouts = LayoutImportacao.query.all()
    for l in layouts: l.map_dict = json.loads(l.mapeamento_json)
    return render_template('layouts.html', layouts=layouts)

@app.route('/excluir-layout/<int:id>')
@login_required
def excluir_layout(id): l = LayoutImportacao.query.get(id); db.session.delete(l); db.session.commit(); return redirect(url_for('layouts'))

@app.route('/templates', methods=['GET', 'POST'])
@login_required
def templates():
    if request.method == 'POST':
        try:
            nome = request.form.get('nome'); tipo = request.form.get('tipo'); conteudo = {}
            if tipo == 'text': conteudo = {"type": "text", "content": request.form.get('text_body')}
            elif tipo == 'media': conteudo = {"type": "media", "mediaType": request.form.get('media_type'), "url": request.form.get('media_url'), "caption": request.form.get('media_caption'), "filename": request.form.get('media_filename')}
            elif tipo == 'button':
                b_types = request.form.getlist('btn_type'); b_titles = request.form.getlist('btn_title'); b_payloads = request.form.getlist('btn_payload'); buttons_list = []
                for i in range(len(b_types)):
                    if b_titles[i]:
                        btn = {"type": b_types[i], "title": b_titles[i]}
                        if b_types[i] in ['url', 'call']: btn["payload"] = b_payloads[i]
                        buttons_list.append(btn)
                conteudo = {"type": "button", "title": request.form.get('btn_msg_title'), "text": request.form.get('btn_msg_body'), "footer": request.form.get('btn_msg_footer'), "buttons": buttons_list}
            elif tipo == 'list':
                l_titles = request.form.getlist('list_row_title'); l_descs = request.form.getlist('list_row_desc'); rows = []
                for i in range(len(l_titles)):
                    if l_titles[i]: rows.append({"title": l_titles[i], "description": l_descs[i], "rowId": f"id_{i}"})
                conteudo = {"type": "list", "buttonText": request.form.get('list_btn_text'), "title": request.form.get('list_msg_title'), "text": request.form.get('list_msg_body'), "description": request.form.get('list_msg_desc'), "sections": [{"title": "Opções", "rows": rows}]}
            elif tipo == 'contact': conteudo = {"type": "contact", "vcard": {"fullName": request.form.get('contact_name'), "displayName": request.form.get('contact_display'), "phoneNumber": request.form.get('contact_phone'), "organization": request.form.get('contact_org')}}
            elif tipo == 'location': conteudo = {"type": "location", "latitude": float(request.form.get('loc_lat')), "longitude": float(request.form.get('loc_long')), "name": request.form.get('loc_name'), "address": request.form.get('loc_address')}
            
            vars_encontradas = set(re.findall(r'\{([A-Z_]+)\}', json.dumps(conteudo)))
            db.session.add(Template(nome=nome, tipo=tipo, conteudo=json.dumps(conteudo), variaveis=",".join(list(vars_encontradas)), modulo="geral"))
            db.session.commit()
            return redirect(url_for('templates'))
        except Exception as e: flash(f'Erro: {str(e)}', 'error')
    all_templates = Template.query.order_by(Template.id.desc()).all()
    for t in all_templates:
        try: t.conteudo_dict = json.loads(t.conteudo)
        except: t.conteudo_dict = {}
    return render_template('templates_msg.html', templates=all_templates)

@app.route('/excluir-template/<int:id>')
@login_required
def excluir_template(id): t = Template.query.get(id); db.session.delete(t); db.session.commit(); return redirect(url_for('templates'))

@app.route('/unidades', methods=['GET', 'POST'])
@login_required
@admin_required
def unidades():
    if request.method == 'POST': db.session.add(Unidade(nome=request.form['nome'])); db.session.commit()
    return render_template('unidades.html', unidades=Unidade.query.all())

@app.route('/editar-unidade/<int:id>', methods=['POST'])
@login_required
@admin_required
def editar_unidade(id): u = Unidade.query.get_or_404(id); u.nome = request.form.get('nome'); db.session.commit(); return redirect(url_for('unidades'))

@app.route('/excluir-unidade/<int:id>')
@login_required
@admin_required
def excluir_unidade(id): u = Unidade.query.get(id); db.session.delete(u); db.session.commit(); return redirect(url_for('unidades'))

@app.route('/config-api', methods=['GET', 'POST'])
@login_required
@admin_required
def config_api():
    if request.method == 'POST':
        uid = request.form.get('unidade_id'); target = int(uid) if (request.form.get('tipo_config') == 'especifica' and uid) else None
        antiga = ConfigAPI.query.filter_by(unidade_id=target).first()
        if antiga: db.session.delete(antiga)
        token_enc = encrypt_token(request.form['bearer_token'])
        db.session.add(ConfigAPI(unidade_id=target, api_host=request.form['api_host'], instance_key=request.form['instance_key'], bearer_token=token_enc))
        db.session.commit()
        return redirect(url_for('config_api'))
    return render_template('config_api.html', configs=ConfigAPI.query.all(), unidades=Unidade.query.all())

@app.route('/excluir-api/<int:id>')
@login_required
@admin_required
def excluir_api(id): c = ConfigAPI.query.get(id); db.session.delete(c); db.session.commit(); return redirect(url_for('config_api'))

@app.route('/gerentes', methods=['GET', 'POST'])
@login_required
@admin_required
def gerentes():
    if request.method == 'POST': db.session.add(Gerente(nome=request.form['nome'], unidade_id=request.form['unidade_id'])); db.session.commit(); return redirect(url_for('gerentes'))
    return render_template('gerentes.html', unidades=Unidade.query.all(), gerentes=Gerente.query.all())

# ... (Outras rotas existentes) ...

# --- MÓDULO DE USUÁRIOS (NOVO) ---
@app.route('/usuarios', methods=['GET', 'POST'])
@login_required
@admin_required
def usuarios():
    # Cadastro de Novo Usuário
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        nivel = request.form.get('nivel_acesso')
        unidade = request.form.get('unidade') # Opcional (para gerentes)

        # Validação simples
        if Usuario.query.filter_by(username=username).first():
            flash('Erro: Este nome de usuário já existe.', 'error')
        elif not username or not password or not nivel:
            flash('Erro: Preencha os campos obrigatórios.', 'error')
        else:
            novo_user = Usuario(username=username, nivel_acesso=nivel, unidade=unidade)
            novo_user.set_password(password) # Hash automático
            db.session.add(novo_user)
            db.session.commit()
            flash('Usuário cadastrado com sucesso!', 'success')
        
        return redirect(url_for('usuarios'))

    # Listagem
    usuarios_lista = Usuario.query.all()
    # Precisamos das unidades para o dropdown (caso seja gerente)
    unidades = Unidade.query.all()
    
    return render_template('usuarios.html', usuarios=usuarios_lista, unidades=unidades)

@app.route('/excluir-usuario/<int:id>')
@login_required
@admin_required
def excluir_usuario(id):
    # Proteção para não se auto-excluir
    if id == current_user.id:
        flash('Ação negada: Você não pode excluir seu próprio usuário.', 'error')
    else:
        u = Usuario.query.get(id)
        if u:
            db.session.delete(u)
            db.session.commit()
            flash('Usuário removido.', 'success')
    return redirect(url_for('usuarios'))

@app.route('/excluir-gerente/<int:id>')
@login_required
@admin_required
def excluir_gerente(id): g = Gerente.query.get(id); db.session.delete(g); db.session.commit(); return redirect(url_for('gerentes'))

@app.route('/respostas', methods=['GET', 'POST'])
@login_required
def respostas():
    if request.method == 'POST':
        palavras = request.form.get('palavras').split(','); palavras = [p.strip().lower() for p in palavras if p.strip()]
        conteudo_resposta = {"type": "text", "content": request.form.get('texto_resposta')}
        db.session.add(RespostaAutomatica(palavras_chave=json.dumps(palavras), resposta=json.dumps(conteudo_resposta)))
        db.session.commit(); return redirect(url_for('respostas'))
    respostas = RespostaAutomatica.query.all()
    for r in respostas: r.palavras_lista = json.loads(r.palavras_chave); r.conteudo_dict = json.loads(r.resposta)
    return render_template('respostas.html', respostas=respostas)

@app.cli.command("criar-admin")
def criar_admin():
    db.create_all()
    if not Usuario.query.filter_by(username='admin').first(): u = Usuario(username='admin', nivel_acesso='admin'); u.set_password('admin123'); db.session.add(u); db.session.commit()

@app.route('/teste', methods=['GET', 'POST'])
@login_required
def teste():
    unidades = Unidade.query.all()
    resultado = None
    
    if request.method == 'POST':
        uid = request.form.get('unidade_id')
        telefone = request.form.get('telefone')
        mensagem = request.form.get('mensagem')
        acao = request.form.get('acao') # 'status' ou 'envio'
        
        conf = get_api_credentials(int(uid)) if uid else None
        
        if not conf:
            resultado = {'tipo': 'erro', 'msg': 'Esta unidade não possui API configurada.'}
        else:
            # Prepara API
            token = decrypt_token(conf.bearer_token)
            api = MegaAPI(conf.api_host, token, conf.instance_key)
            
            if acao == 'status':
                resp = api.verificar_status()
                # A Mega API retorna 'error': False quando está tudo ok
                if resp.get('error') is False:
                    # Verifica se tem dados de conexão
                    instancia = resp.get('instance_key', 'Desconhecida')
                    user = resp.get('user', {}).get('id', 'Não pareado')
                    resultado = {'tipo': 'sucesso', 'msg': f"Conexão Ativa! Instância: {instancia} | WhatsApp: {user}"}
                else:
                    resultado = {'tipo': 'erro', 'msg': f"Erro de Conexão: {resp.get('message', 'Desconhecido')}"}
            
            elif acao == 'envio':
                if not telefone or not mensagem:
                    resultado = {'tipo': 'erro', 'msg': 'Telefone e mensagem são obrigatórios para o envio.'}
                else:
                    # Usa o método interno que já formata o número e trata o JSON
                    conteudo_json = json.dumps({"type": "text", "content": mensagem})
                    resp = api.enviar_mensagem_template(telefone, conteudo_json)
                    
                    if resp.get('error') is False:
                        resultado = {'tipo': 'sucesso', 'msg': f"Mensagem enviada! ID: {resp.get('key', {}).get('id')}"}
                    else:
                        resultado = {'tipo': 'erro', 'msg': f"Falha no envio: {resp.get('message')}"}

    return render_template('teste.html', unidades=unidades, resultado=resultado)

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(debug=True, port=5000)