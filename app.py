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
from sqlalchemy import func, desc
from datetime import datetime, timedelta, date
from werkzeug.utils import secure_filename
from functools import wraps
from cryptography.fernet import Fernet

# --- CONFIGURAÇÃO GERAL ---
app = Flask(__name__)
app.secret_key = 'chave_super_secreta_academia' # Em produção, use variáveis de ambiente
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
            
            if item.get('telefone'):
                item['telefone'] = re.sub(r'\D', '', item['telefone'])
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

# --- MODELOS DO BANCO DE DADOS ---

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

# --- MODELOS CHATFLOW (ESSENCIAIS PARA O CHAT) ---
class Conversa(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    telefone = db.Column(db.String(20), unique=True, nullable=False)
    nome_cliente = db.Column(db.String(100))
    unidade_id = db.Column(db.Integer, db.ForeignKey('unidade.id'), nullable=True)
    agente_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=True)
    status = db.Column(db.String(20), default='aberto')
    ultima_mensagem = db.Column(db.Text)
    data_atualizacao = db.Column(db.DateTime, default=datetime.now)
    etiquetas = db.Column(db.Text)
    mensagens = db.relationship('MensagemChat', backref='conversa_ref', lazy=True, cascade="all, delete-orphan")

class MensagemChat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversa_id = db.Column(db.Integer, db.ForeignKey('conversa.id'), nullable=False)
    remetente = db.Column(db.String(20)) # 'cliente' ou 'agente'
    tipo = db.Column(db.String(20))
    conteudo = db.Column(db.Text)
    data_hora = db.Column(db.DateTime, default=datetime.now)
    status = db.Column(db.String(20))

# --- INTEGRAÇÃO MEGA API ---
class MegaAPI:
    def __init__(self, host, token, instance_key):
        host = host.strip().rstrip('/')
        if not host.startswith("http"): host = f"https://{host}"
        self.host = host
        self.instance_key = instance_key
        self.headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

    def _format_number(self, to):
        to = str(to).strip()
        if "@" in to: return to
        return f"{to}@s.whatsapp.net"

    def verificar_status(self):
        try:
            url = f"{self.host}/rest/instance/{self.instance_key}"
            resp = requests.get(url, headers=self.headers, timeout=10)
            return resp.json()
        except Exception as e: return {"error": True, "message": str(e)}

    def _post(self, endpoint, payload):
        time.sleep(random.uniform(1, 2)) # Delay reduzido para chat interativo
        try:
            url = f"{self.host}/rest/sendMessage/{self.instance_key}/{endpoint}"
            resp = requests.post(url, json=payload, headers=self.headers, timeout=15)
            return resp.json()
        except Exception as e: return {"error": True, "message": str(e)}

    def enviar_texto(self, to, text):
        return self._post("text", {"messageData": {"to": self._format_number(to), "text": text}})

    def enviar_mensagem_template(self, to, template_conteudo_json, dados_replace=None):
        try:
            to_formatted = self._format_number(to)
            content = json.loads(template_conteudo_json) if isinstance(template_conteudo_json, str) else template_conteudo_json
            
            if dados_replace:
                def replace_vars(obj):
                    if isinstance(obj, str):
                        for k, v in dados_replace.items():
                            obj = obj.replace(f"{{{k}}}", str(v))
                        return obj
                    elif isinstance(obj, dict): return {k: replace_vars(v) for k, v in obj.items()}
                    elif isinstance(obj, list): return [replace_vars(i) for i in obj]
                    return obj
                content = replace_vars(content)

            msg_type = content.get('type')
            
            if msg_type == 'text':
                return self._post("text", {"messageData": {"to": to_formatted, "text": content.get('content')}})
            elif msg_type == 'media':
                return self._post("mediaUrl", {"messageData": {"to": to_formatted, "url": content.get('url'), "type": content.get('mediaType', 'image'), "caption": content.get('caption', ''), "mimeType": content.get('mimeType', '')}})
            elif msg_type == 'button':
                return self._post("buttonMessage", {"messageData": {"to": to_formatted, "title": content.get('title'), "text": content.get('text'), "footer": content.get('footer'), "buttons": content.get('buttons')}})
            elif msg_type == 'list':
                return self._post("listMessage", {"messageData": {"to": to_formatted, "buttonText": content.get('buttonText'), "text": content.get('text'), "title": content.get('title'), "description": content.get('description'), "sections": content.get('sections'), "listType": 0}})
            elif msg_type == 'contact':
                return self._post("contactMessage", {"messageData": {"to": to_formatted, "vcard": content.get('vcard')}})
            elif msg_type == 'location':
                return self._post("locationMessage", {"messageData": {"to": to_formatted, "latitude": content.get('latitude'), "longitude": content.get('longitude'), "name": content.get('name'), "address": content.get('address')}})
            return {"error": True, "message": "Tipo desconhecido"}
        except Exception as e: return {"error": True, "message": str(e)}

def get_api_credentials(unidade_id=None):
    if unidade_id:
        config = ConfigAPI.query.filter_by(unidade_id=unidade_id).first()
        if config: return config
    return ConfigAPI.query.filter_by(unidade_id=None).first()

# --- CONTROLE DE ACESSO ---
@login_manager.user_loader
def load_user(user_id): return Usuario.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.nivel_acesso != 'admin':
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# --- ROTAS ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = Usuario.query.filter_by(username=request.form.get('username')).first()
        if user and user.check_password(request.form.get('password')):
            login_user(user)
            return redirect(url_for('index'))
        flash('Credenciais inválidas.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout(): logout_user(); return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    total_enviadas = LogEnvios.query.count()
    total_entregues = LogEnvios.query.filter_by(status_entrega='DELIVERED').count()
    por_modulo = db.session.query(LogEnvios.modulo, func.count(LogEnvios.id)).group_by(LogEnvios.modulo).all()
    por_unidade_raw = db.session.query(LogEnvios.unidade, func.count(LogEnvios.id)).group_by(LogEnvios.unidade).all()
    por_unidade = [{'nome': u[0], 'qtd': u[1], 'percentual': round(u[1]/total_enviadas*100, 1) if total_enviadas else 0} for u in por_unidade_raw]
    return render_template('index.html', total_enviadas=total_enviadas, total_entregues=total_entregues, por_modulo=por_modulo, por_unidade=por_unidade, unidades=Unidade.query.all())

# --- CHATFLOW (ROTAS DO MÓDULO DE CHAT) ---
@app.route('/chatflow')
@login_required
def chatflow():
    agentes = Usuario.query.all()
    templates = Template.query.all()
    return render_template('chatflow.html', agentes=agentes, templates=templates)

@app.route('/api/chats', methods=['GET'])
@login_required
def api_get_chats():
    filtro = request.args.get('filtro', 'todos')
    query = Conversa.query
    if filtro == 'meus': query = query.filter_by(agente_id=current_user.id)
    elif filtro == 'nao_lidos': query = query.filter_by(status='aberto')
    conversas = query.order_by(Conversa.data_atualizacao.desc()).all()
    data = [{'id': c.id, 'nome': c.nome_cliente or c.telefone, 'telefone': c.telefone, 'ultima_msg': c.ultima_mensagem, 'hora': c.data_atualizacao.strftime('%H:%M'), 'status': c.status, 'etiquetas': json.loads(c.etiquetas) if c.etiquetas else [], 'agente_id': c.agente_id} for c in conversas]
    return jsonify(data)

@app.route('/api/messages/<int:chat_id>', methods=['GET'])
@login_required
def api_get_messages(chat_id):
    msgs = MensagemChat.query.filter_by(conversa_id=chat_id).order_by(MensagemChat.data_hora).all()
    data = [{'tipo': m.tipo, 'conteudo': m.conteudo, 'lado': 'right' if m.remetente == 'agente' else 'left', 'hora': m.data_hora.strftime('%H:%M')} for m in msgs]
    return jsonify(data)

@app.route('/api/send', methods=['POST'])
@login_required
def api_send_message():
    data = request.json
    chat_id = data.get('chat_id')
    texto = data.get('texto')
    conversa = Conversa.query.get(chat_id)
    if not conversa: return jsonify({'error': 'Chat não encontrado'}), 404
    conf = get_api_credentials(conversa.unidade_id)
    if not conf: return jsonify({'error': 'API não configurada'}), 400
    token = decrypt_token(conf.bearer_token)
    api = MegaAPI(conf.api_host, token, conf.instance_key)
    resp = api.enviar_texto(conversa.telefone, texto)
    if not resp.get('error'):
        msg = MensagemChat(conversa_id=chat_id, remetente='agente', tipo='text', conteudo=texto, status='sent')
        conversa.ultima_mensagem = texto
        conversa.data_atualizacao = datetime.now()
        db.session.add(msg); db.session.commit()
        return jsonify({'status': 'ok'})
    return jsonify({'error': resp.get('message')}), 500

@app.route('/api/update_chat', methods=['POST'])
@login_required
def api_update_chat():
    data = request.json
    conversa = Conversa.query.get(data.get('chat_id'))
    if 'agente_id' in data: conversa.agente_id = int(data['agente_id']) if data['agente_id'] else None
    if 'status' in data: conversa.status = data['status']
    if 'etiqueta_add' in data:
        tags = json.loads(conversa.etiquetas) if conversa.etiquetas else []
        if data['etiqueta_add'] not in tags: tags.append(data['etiqueta_add']); conversa.etiquetas = json.dumps(tags)
    if 'etiqueta_remove' in data:
        tags = json.loads(conversa.etiquetas) if conversa.etiquetas else []
        if data['etiqueta_remove'] in tags: tags.remove(data['etiqueta_remove']); conversa.etiquetas = json.dumps(tags)
    db.session.commit()
    return jsonify({'status': 'ok'})

# --- WEBHOOK (RECEBIMENTO) ---
@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.json
    try:
        msg_data = data.get('data', {})
        from_number = msg_data.get('from')
        # Ignora mensagens enviadas por mim (no próprio celular)
        if msg_data.get('fromMe'): return jsonify({'status': 'ignored'})
        
        telefone = from_number.split('@')[0] if from_number else None
        texto = msg_data.get('body', '')
        
        if telefone and texto:
            # Lógica ChatFlow: Salvar conversa
            conversa = Conversa.query.filter_by(telefone=telefone).first()
            if not conversa:
                conversa = Conversa(telefone=telefone, nome_cliente=msg_data.get('pushName', 'Cliente'), status='aberto')
                db.session.add(conversa); db.session.commit()
            
            msg = MensagemChat(conversa_id=conversa.id, remetente='cliente', tipo='text', conteudo=texto, status='received')
            conversa.ultima_mensagem = texto
            conversa.data_atualizacao = datetime.now()
            conversa.status = 'aberto'
            db.session.add(msg)
            
            # Lógica Autoresposta
            auto = RespostaAutomatica.query.filter(RespostaAutomatica.ativo == True).all()
            for r in auto:
                palavras = json.loads(r.palavras_chave)
                if any(p in texto.lower() for p in palavras):
                    # Envia resposta
                    conf = get_api_credentials()
                    if conf:
                        token = decrypt_token(conf.bearer_token)
                        api = MegaAPI(conf.api_host, token, conf.instance_key)
                        api.enviar_mensagem_template(telefone, r.resposta)
                        # Registra no chat
                        tpl_content = json.loads(r.resposta).get('content', '[AutoResposta]')
                        db.session.add(MensagemChat(conversa_id=conversa.id, remetente='agente', tipo='text', conteudo=tpl_content, status='sent'))
                        conversa.ultima_mensagem = tpl_content
                    break
            
            db.session.commit()
    except Exception as e: print(f"Webhook Error: {e}")
    return jsonify({'status': 'ok'})

# --- ROTAS PADRÃO ---
@app.route('/usuarios', methods=['GET', 'POST'])
@login_required
@admin_required
def usuarios():
    if request.method == 'POST':
        u = Usuario(username=request.form['username'], nivel_acesso=request.form['nivel_acesso'], unidade=request.form.get('unidade'))
        u.set_password(request.form['password'])
        db.session.add(u); db.session.commit(); flash('Usuário criado', 'success')
        return redirect(url_for('usuarios'))
    return render_template('usuarios.html', usuarios=Usuario.query.all(), unidades=Unidade.query.all())

@app.route('/excluir-usuario/<int:id>')
@login_required
@admin_required
def excluir_usuario(id):
    if id != current_user.id: db.session.delete(Usuario.query.get(id)); db.session.commit()
    return redirect(url_for('usuarios'))

@app.route('/boas-vindas', methods=['GET', 'POST'])
@login_required
def boas_vindas():
    layouts = LayoutImportacao.query.all()
    templates = Template.query.filter_by(modulo='geral').all()
    preview = []
    lid, tid = None, None
    if request.method == 'POST':
        if 'file' in request.files:
            file = request.files['file']; lid = request.form.get('layout_id'); tid = request.form.get('template_id')
            if file and lid and tid:
                layout = LayoutImportacao.query.get(lid); template = Template.query.get(tid)
                path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename)); file.save(path)
                try:
                    map_dict = json.loads(layout.mapeamento_json); dados = processar_upload_excel(path, map_dict)
                    tpl_json = json.loads(template.conteudo); msg_base = tpl_json.get('content', tpl_json.get('text', ''))
                    for d in dados:
                        uid = None; unid_nome = d.get('unidade', '').strip()
                        if unid_nome:
                            u_db = Unidade.query.filter(Unidade.nome.ilike(f"%{unid_nome}%")).first(); uid = u_db.id if u_db else None
                        msg_prev = msg_base
                        for k, v in d.items(): msg_prev = msg_prev.replace(f"{{{k.upper()}}}", str(v))
                        preview.append({'dados': d, 'status': 'Pronto', 'unidade_id': uid, 'template_id': template.id, 'unidade_nome': unid_nome, 'msg_preview': msg_prev, 'nome': d.get('aluno')})
                except Exception as e: flash(f"Erro: {e}", 'error')
        elif 'confirmar_envio' in request.form:
            dados_envio = request.form.getlist('dados_envio'); sucesso = 0
            for item in dados_envio:
                try:
                    d = json.loads(item.replace("'", '"')); conf = get_api_credentials(d['unidade_id'])
                    if conf:
                        token = decrypt_token(conf.bearer_token); api = MegaAPI(conf.api_host, token, conf.instance_key)
                        tpl = Template.query.get(d['template_id']); replace = {k.upper(): v for k, v in d['dados'].items()}
                        resp = api.enviar_mensagem_template(d['dados']['telefone'], tpl.conteudo, replace)
                        if not resp.get('error'): sucesso += 1; db.session.add(LogEnvios(telefone=d['dados']['telefone'], unidade=d['dados'].get('unidade'), modulo='boas_vindas', message_id=resp.get('key', {}).get('id'), status_entrega='PENDING'))
                except: pass
            db.session.commit(); flash(f'{sucesso} enviadas.', 'success'); return redirect(url_for('boas_vindas'))
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
            file = request.files['file']; lid = request.form.get('layout_id')
            if file and lid:
                layout = LayoutImportacao.query.get(lid); path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename)); file.save(path)
                try:
                    map_dict = json.loads(layout.mapeamento_json); dados = processar_upload_excel(path, map_dict)
                    for d in dados:
                        dias_sem_acesso = calcular_dias_sem_acesso(d.get('data_hora_ultimo_acesso', '')); meses_ativo = calcular_meses_ativo(d.get('inicio_plano'), d.get('tempo_ativo'))
                        debitos = int(float(d.get('debitos', 0))) if d.get('debitos') else 0; valor = float(d.get('valor', 0)) if d.get('valor') else 0.0
                        d.update({'dias_sem_acesso': dias_sem_acesso, 'meses_ativo': meses_ativo})
                        template_match = None; status = "Sem Regra"
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
                            template_match = tpl; break
                        if template_match:
                            last_cob = HistoricoCobranca.query.filter_by(telefone=d['telefone']).order_by(HistoricoCobranca.data_envio.desc()).first()
                            if last_cob and last_cob.proxima_cobranca_permitida and last_cob.proxima_cobranca_permitida > date.today(): status = f"Cooldown"; template_match = None
                            else: status = "Pronto"
                        msg_prev = ""
                        if template_match:
                            tpl_json = json.loads(template_match.conteudo); msg_prev = tpl_json.get('content', tpl_json.get('text', ''))
                            for k, v in d.items(): msg_prev = msg_prev.replace(f"{{{k.upper()}}}", str(v))
                        if template_match or "Cooldown" in status:
                            preview.append({'dados': d, 'status': status, 'unidade_id': None, 'template_id': template_match.id if template_match else None, 'template_nome': template_match.nome if template_match else "-", 'msg_preview': msg_prev, 'nome': d.get('aluno'), 'detalhes': f"{debitos} débitos | {dias_sem_acesso}d s/ acesso"})
                except Exception as e: flash(f"Erro: {e}", 'error')
        elif 'confirmar_envio' in request.form:
            dados = request.form.getlist('dados_envio'); sucesso = 0
            for item in dados:
                try:
                    d = json.loads(item.replace("'", '"')); conf = get_api_credentials(d['unidade_id'])
                    if d['status'] == "Pronto" and conf:
                        token = decrypt_token(conf.bearer_token); api = MegaAPI(conf.api_host, token, conf.instance_key)
                        tpl = Template.query.get(d['template_id']); regras = json.loads(tpl.regras)
                        replace = {k.upper(): v for k, v in d['dados'].items()}
                        resp = api.enviar_mensagem_template(d['dados']['telefone'], tpl.conteudo, replace)
                        if not resp.get('error'):
                            sucesso += 1; db.session.add(LogEnvios(telefone=d['dados']['telefone'], modulo='cobranca', message_id=resp.get('key', {}).get('id'), status_entrega='PENDING'))
                            prox = date.today() + timedelta(days=int(regras.get('cooldown', 7))); db.session.add(HistoricoCobranca(telefone=d['dados']['telefone'], proxima_cobranca_permitida=prox, template_usado=tpl.nome))
                except: pass
            db.session.commit(); flash(f'{sucesso} cobranças enviadas.', 'success'); return redirect(url_for('cobranca'))
    return render_template('cobranca.html', layouts=layouts, preview=preview, layout_selecionado=int(lid) if lid else None)

@app.route('/config-regras/<int:id>', methods=['GET', 'POST'])
@login_required
def config_regras(id):
    tpl = Template.query.get_or_404(id)
    if request.method == 'POST':
        regras = {
            "min_debitos": int(request.form.get('min_debitos', 0)), "max_debitos": int(request.form.get('max_debitos', 999)),
            "min_dias": int(request.form.get('min_dias', 0)), "max_dias": int(request.form.get('max_dias', 999)),
            "min_valor": float(request.form.get('min_valor', 0)), "cooldown": int(request.form.get('cooldown', 7)),
            "unidade_filtro": request.form.get('unidade_filtro'), "plano_filtro": request.form.get('plano_filtro'),
            "min_meses_ativo": int(request.form.get('min_meses_ativo', 0))
        }
        tpl.regras = json.dumps(regras); tpl.modulo = 'cobranca'; db.session.commit(); return redirect(url_for('templates'))
    regras = json.loads(tpl.regras) if tpl.regras else {}; unidades = Unidade.query.all()
    return render_template('config_regras.html', tpl=tpl, regras=regras, unidades=unidades)

@app.route('/layouts', methods=['GET', 'POST'])
@login_required
def layouts():
    if request.method == 'POST':
        mapeamento = {}; 
        for key, val in request.form.items(): 
            if key.startswith('map_') and val.strip(): mapeamento[key.replace('map_', '')] = val.strip()
        db.session.add(LayoutImportacao(nome=request.form['nome'], mapeamento_json=json.dumps(mapeamento))); db.session.commit(); return redirect(url_for('layouts'))
    layouts = LayoutImportacao.query.all(); 
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
                    if b_titles[i]: buttons_list.append({"type": b_types[i], "title": b_titles[i], "payload": b_payloads[i] if b_types[i] in ['url', 'call'] else ""})
                conteudo = {"type": "button", "title": request.form.get('btn_msg_title'), "text": request.form.get('btn_msg_body'), "footer": request.form.get('btn_msg_footer'), "buttons": buttons_list}
            elif tipo == 'list':
                l_titles = request.form.getlist('list_row_title'); l_descs = request.form.getlist('list_row_desc'); rows = []
                for i in range(len(l_titles)):
                    if l_titles[i]: rows.append({"title": l_titles[i], "description": l_descs[i], "rowId": f"id_{i}"})
                conteudo = {"type": "list", "buttonText": request.form.get('list_btn_text'), "title": request.form.get('list_msg_title'), "text": request.form.get('list_msg_body'), "description": request.form.get('list_msg_desc'), "sections": [{"title": "Opções", "rows": rows}]}
            elif tipo == 'contact': conteudo = {"type": "contact", "vcard": {"fullName": request.form.get('contact_name'), "displayName": request.form.get('contact_display'), "phoneNumber": request.form.get('contact_phone'), "organization": request.form.get('contact_org')}}
            elif tipo == 'location': conteudo = {"type": "location", "latitude": float(request.form.get('loc_lat')), "longitude": float(request.form.get('loc_long')), "name": request.form.get('loc_name'), "address": request.form.get('loc_address')}
            
            vars_encontradas = set(re.findall(r'\{([A-Z_]+)\}', json.dumps(conteudo)))
            db.session.add(Template(nome=nome, tipo=tipo, conteudo=json.dumps(conteudo), variaveis=",".join(list(vars_encontradas)), modulo="geral")); db.session.commit()
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
    if request.method == 'POST': db.session.add(Unidade(nome=request.form['nome'])); db.session.commit(); flash('Unidade criada!', 'success')
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
        antiga = ConfigAPI.query.filter_by(unidade_id=target).first(); 
        if antiga: db.session.delete(antiga)
        token_enc = encrypt_token(request.form['bearer_token'])
        db.session.add(ConfigAPI(unidade_id=target, api_host=request.form['api_host'], instance_key=request.form['instance_key'], bearer_token=token_enc)); db.session.commit()
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
        db.session.add(RespostaAutomatica(palavras_chave=json.dumps(palavras), resposta=json.dumps(conteudo_resposta))); db.session.commit(); return redirect(url_for('respostas'))
    respostas = RespostaAutomatica.query.all()
    for r in respostas: r.palavras_lista = json.loads(r.palavras_chave); r.conteudo_dict = json.loads(r.resposta)
    return render_template('respostas.html', respostas=respostas)

@app.route('/teste', methods=['GET', 'POST'])
@login_required
def teste():
    unidades = Unidade.query.all(); resultado = None
    if request.method == 'POST':
        uid = request.form.get('unidade_id'); telefone = request.form.get('telefone'); mensagem = request.form.get('mensagem'); acao = request.form.get('acao')
        conf = get_api_credentials(int(uid)) if uid else None
        if not conf: resultado = {'tipo': 'erro', 'msg': 'Sem API.'}
        else:
            token = decrypt_token(conf.bearer_token); api = MegaAPI(conf.api_host, token, conf.instance_key)
            if acao == 'status':
                resp = api.verificar_status()
                resultado = {'tipo': 'sucesso', 'msg': 'Conectado'} if not resp.get('error') else {'tipo': 'erro', 'msg': 'Erro'}
            elif acao == 'envio':
                resp = api.enviar_mensagem_template(telefone, json.dumps({"type": "text", "content": mensagem}))
                resultado = {'tipo': 'sucesso', 'msg': 'Enviado'} if not resp.get('error') else {'tipo': 'erro', 'msg': 'Erro envio'}
    return render_template('teste.html', unidades=unidades, resultado=resultado)

@app.cli.command("criar-admin")
def criar_admin():
    db.create_all()
    if not Usuario.query.filter_by(username='admin').first():
        u = Usuario(username='admin', nivel_acesso='admin'); u.set_password('admin123'); db.session.add(u); db.session.commit(); print("Admin criado.")

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(debug=True, port=5000)