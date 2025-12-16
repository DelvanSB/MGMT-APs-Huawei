#!/usr/bin/env python3
"""
Backend Flask - Sistema de Gerenciamento de APs com Autenticação
Huawei S6730 AC Controller
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import paramiko
import time
import re
import logging
from datetime import datetime, timedelta
from functools import wraps
import os
import jwt
import json
from werkzeug.security import generate_password_hash, check_password_hash

from dotenv import load_dotenv

# Carregar variáveis do .env
load_dotenv()

app = Flask(__name__, static_folder='build', static_url_path='')
CORS(app)

# ==================== CONFIGURAÇÕES ====================

SWITCH_CONFIG = {
    'host': os.getenv('SWITCH_HOST', '192.168.1.1'),
    'port': int(os.getenv('SWITCH_PORT', 22)),
    'username': os.getenv('SWITCH_USER', 'api-manager'),
    'password': os.getenv('SWITCH_PASSWORD', 'SuaSenhaAqui'),
    'timeout': 15
}

# Configuração JWT
JWT_SECRET = os.getenv('JWT_SECRET', 'sua-chave-secreta-mude-isso')  # IMPORTANTE: Mude em produção!
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_HOURS = 8  # Token expira em 8 horas

# Arquivo de usuários
USERS_FILE = 'users.json'

# ==================== LOGGING ====================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ap_management.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ==================== GERENCIAMENTO DE USUÁRIOS ====================

def load_users():
    """Carrega usuários do arquivo JSON"""
    if not os.path.exists(USERS_FILE):
        # Cria arquivo inicial com usuário padrão
        default_users = {
            "maycon": {
                "password": generate_password_hash("maycon123"),  # Senha padrão: maycon123
                "name": "Maycon",
                "role": "operator",
                "active": True
            }
        }
        save_users(default_users)
        return default_users
    
    try:
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Erro ao carregar usuários: {str(e)}")
        return {}


def save_users(users):
    """Salva usuários no arquivo JSON"""
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Erro ao salvar usuários: {str(e)}")
        return False


def authenticate_user(username, password):
    """Autentica usuário"""
    users = load_users()
    
    if username not in users:
        return None
    
    user = users[username]
    
    if not user.get('active', True):
        return None
    
    if check_password_hash(user['password'], password):
        return {
            'username': username,
            'name': user['name'],
            'role': user['role']
        }
    
    return None


def generate_token(user_data):
    """Gera token JWT"""
    payload = {
        'username': user_data['username'],
        'name': user_data['name'],
        'role': user_data['role'],
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXP_DELTA_HOURS)
    }
    
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def verify_token(token):
    """Verifica e decodifica token JWT"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def token_required(f):
    """Decorador para proteger rotas que requerem autenticação"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'success': False, 'error': 'Token não fornecido'}), 401
        
        # Remove "Bearer " se presente
        if token.startswith('Bearer '):
            token = token[7:]
        
        user_data = verify_token(token)
        
        if not user_data:
            return jsonify({'success': False, 'error': 'Token inválido ou expirado'}), 401
        
        # Adiciona dados do usuário ao request
        request.current_user = user_data
        
        return f(*args, **kwargs)
    
    return decorated


# ==================== CONEXÃO SSH ====================

class SwitchConnection:
    """Gerencia conexão SSH com o switch Huawei (VRP)"""

    def __init__(self, config):
        self.config = config
        self.client = None
        self.shell = None

    def connect(self):
        """Estabelece conexão SSH"""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                hostname=self.config['host'],
                port=self.config['port'],
                username=self.config['username'],
                password=self.config['password'],
                timeout=self.config['timeout'],
                look_for_keys=False,
                allow_agent=False
            )

            self.shell = self.client.invoke_shell()
            time.sleep(1)

            # Limpa banner inicial
            self.shell.recv(65535)

            # Desabilita paginação (fundamental para outputs grandes)
            self.shell.send('screen-length 0 temporary\n')
            time.sleep(0.3)
            self.shell.recv(65535)

            logger.info(f"Conectado ao switch {self.config['host']}")
            return True

        except Exception as e:
            logger.error(f"Erro ao conectar: {str(e)}")
            return False

    def execute_command(self, command, wait_time=0.3, max_loops=1000):
        """
        Executa comando SSH e lê a saída COMPLETA
        A leitura só termina quando o prompt reaparece
        """
        output = ""

        try:
            self.shell.send(command + '\n')
            time.sleep(wait_time)

            loops = 0

            while loops < max_loops:
                chunk = self.shell.recv(65535).decode('utf-8', errors='ignore')
                output += chunk
                loops += 1

                # Critério correto de término: prompt no FINAL do chunk
                if re.search(r'(<[^>]+>|\[[^\]]+\])\s*$', chunk.strip()):
                    break

            return output

        except Exception as e:
            logger.error(f"Erro ao executar '{command}': {str(e)}")
            return None

    def execute_commands(self, commands, wait_time=0.3):
        """Executa lista de comandos sequencialmente"""
        outputs = []
        for cmd in commands:
            outputs.append(self.execute_command(cmd, wait_time))
        return outputs

    def disconnect(self):
        """Fecha conexão SSH"""
        if self.client:
            self.client.close()
            logger.info("Desconectado do switch")



# ==================== PARSERS ====================

def parse_ap_list(output):
    """Parse do 'display ap all' ou 'display ap ap-group NOME'"""
    aps = []
    lines = output.split('\n')
    
    for line in lines:
        match = re.search(
            r'^\s*(\d+)\s+'
            r'([0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4})\s+'
            r'(.+?)\s+'                 # NOME DO AP (corrigido)
            r'(\S+)\s+'                 # group
            r'(\S+)\s+'                 # ip
            r'(\S+)\s+'                 # type
            r'(nor|fault|idle)\s+'      # state
            r'(\d+)\s+'
            r'(\S+)',
            line,
            re.IGNORECASE
        )
        
        if match:
            ap_id, mac, name, group, ip, ap_type, state, sta, uptime = match.groups()
            
            status_map = {
                'nor': 'Online',
                'fault': 'Offline',
                'idle': 'Idle'
            }
            
            aps.append({
                'id': ap_id,
                'mac': mac.lower(),
                'name': name.strip(),
                'group': group,
                'ip': ip if ip != '-' else None,
                'type': ap_type,
                'state': status_map.get(state, state),
                'sta': int(sta),
                'uptime': uptime if uptime != '-' else None
            })
    
    return aps


def parse_ap_groups(output):
    """Parse do 'display ap-group all'"""
    groups = []
    total_aps = 0  # Armazenar o total de APs
    lines = output.split('\n')

    for line in lines:
        line = line.strip()

        # Ignorar a linha "Total"
        if line.lower().startswith('total'):
            total_aps = int(line.split()[1])  # Aqui pegamos apenas a quantidade de APs
            continue

        match = re.search(r'^(\S+)\s+(\d+)$', line)
        if match:
            name, count = match.groups()
            groups.append({
                'name': name,
                'count': int(count)
            })

    return groups, total_aps


def parse_ap_config(output):
    """Parse do 'display ap config-info ap-id X'"""
    config = {
        'basic': {},
        'radios': []
    }
    
    lines = output.split('\n')
    current_radio = None
    current_vap = None
    
    for line in lines:
        line = line.strip()
        
        if 'AP MAC' in line:
            config['basic']['mac'] = re.search(r':\s*(\S+)', line).group(1) if re.search(r':\s*(\S+)', line) else None
        elif 'AP SN' in line:
            config['basic']['serial'] = re.search(r':\s*(\S+)', line).group(1) if re.search(r':\s*(\S+)', line) else None
        elif 'AP type' in line and 'AP type ID' not in line:
            config['basic']['type'] = re.search(r':\s*(\S+)', line).group(1) if re.search(r':\s*(\S+)', line) else None
        elif 'AP name' in line and 'AP MAC' not in line:
            config['basic']['name'] = re.search(r':\s*(.+)', line).group(1).strip() if re.search(r':\s*(.+)', line) else None
        elif 'AP group' in line and 'AP branch' not in line:
            config['basic']['group'] = re.search(r':\s*(\S+)', line).group(1) if re.search(r':\s*(\S+)', line) else None
        elif 'Country code' in line:
            config['basic']['country_code'] = re.search(r':\s*(\S+)', line).group(1) if re.search(r':\s*(\S+)', line) else None
        
        if 'Radio 0 configurations:' in line:
            current_radio = {'id': 0, 'vaps': []}
            config['radios'].append(current_radio)
        elif 'Radio 1 configurations:' in line:
            current_radio = {'id': 1, 'vaps': []}
            config['radios'].append(current_radio)
        
        if current_radio is not None and current_vap is None:
            if 'Radio band' in line:
                current_radio['band'] = re.search(r':\s*(\S+)', line).group(1) if re.search(r':\s*(\S+)', line) else None
            elif 'Radio type' in line:
                current_radio['type'] = re.search(r':\s*(\S+)', line).group(1) if re.search(r':\s*(\S+)', line) else None
            elif 'Actual channel/bandwidth' in line:
                match = re.search(r':\s*(\d+)/(\S+)', line)
                if match:
                    current_radio['channel'] = match.group(1)
                    current_radio['bandwidth'] = match.group(2)
            elif 'Actual EIRP' in line:
                current_radio['eirp'] = re.search(r':\s*(\d+)', line).group(1) if re.search(r':\s*(\d+)', line) else None
        
        if current_radio is not None:
            if 'WLAN ID' in line:
                wlan_id = re.search(r'WLAN ID (\d+):', line)
                if wlan_id:
                    current_vap = {'wlan_id': wlan_id.group(1)}
                    current_radio['vaps'].append(current_vap)
            elif current_vap is not None:
                if 'SSID' in line and 'Deny-broadcast' not in line:
                    current_vap['ssid'] = re.search(r':\s*(.+)', line).group(1).strip() if re.search(r':\s*(.+)', line) else None
                elif 'Authen mode' in line:
                    current_vap['auth'] = re.search(r':\s*(.+)', line).group(1).strip() if re.search(r':\s*(.+)', line) else None
                elif 'Service vlan' in line:
                    current_vap['vlan'] = re.search(r':\s*(\d+)', line).group(1) if re.search(r':\s*(\d+)', line) else None
                elif 'Encrypt mode' in line:
                    current_vap['encryption'] = re.search(r':\s*(\S+)', line).group(1) if re.search(r':\s*(\S+)', line) else None
                    current_vap = None
    
    return config


def parse_ap_run_info(output):
    """Parse do 'display ap run-info ap-id X'"""
    info = {}
    lines = output.split('\n')
    
    for line in lines:
        line = line.strip()
        
        if 'AP type' in line and ':' in line:
            info['type'] = re.search(r':\s*(.+)', line).group(1).strip() if re.search(r':\s*(.+)', line) else None
        elif 'Software version' in line:
            info['software_version'] = re.search(r':\s*(.+)', line).group(1).strip() if re.search(r':\s*(.+)', line) else None
        elif 'Hardware version' in line:
            info['hardware_version'] = re.search(r':\s*(.+)', line).group(1).strip() if re.search(r':\s*(.+)', line) else None
        elif 'Online time' in line:
            info['online_time'] = re.search(r':\s*(.+)', line).group(1).strip() if re.search(r':\s*(.+)', line) else None
        elif 'IP address' in line and 'IP mask' not in line:
            info['ip'] = re.search(r':\s*(\S+)', line).group(1) if re.search(r':\s*(\S+)', line) else None
        elif 'IP mask' in line:
            info['mask'] = re.search(r':\s*(\S+)', line).group(1) if re.search(r':\s*(\S+)', line) else None
        elif 'Gateway' in line:
            info['gateway'] = re.search(r':\s*(\S+)', line).group(1) if re.search(r':\s*(\S+)', line) else None
    
    return info


def parse_stations(output):
    """Parse do 'display station ap-id X'"""
    stations = []
    lines = output.split('\n')
    
    for line in lines:
        match = re.search(
            r'^([0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4})\s+'
            r'(\d+/\d+)\s+'
            r'(\S+)\s+'
            r'(\S+)\s+'
            r'(\S+)\s+'
            r'(-?\d+)\s+'
            r'(\d+)\s+'
            r'(\S+)\s+'
            r'(.+)',
            line, re.IGNORECASE
        )
        
        if match:
            mac, rf_wlan, band, sta_type, rxtx, rssi, vlan, ip, ssid = match.groups()
            
            stations.append({
                'mac': mac.lower(),
                'rf_wlan': rf_wlan,
                'band': band,
                'type': sta_type,
                'rx_tx': rxtx,
                'rssi': int(rssi),
                'vlan': int(vlan),
                'ip': ip if ip != '-' else None,
                'ssid': ssid.strip()
            })
    
    return stations


# ==================== DECORADOR SWITCH ====================

def with_switch_connection(f):
    """Decorador para gerenciar conexão SSH"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        conn = SwitchConnection(SWITCH_CONFIG)
        if not conn.connect():
            return jsonify({
                'success': False,
                'error': 'Não foi possível conectar ao switch'
            }), 500
        
        try:
            result = f(conn, *args, **kwargs)
            return result
        finally:
            conn.disconnect()
    
    return decorated_function


# ==================== ROTAS DE AUTENTICAÇÃO ====================

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Endpoint de login"""
    try:
        data = request.json
        username = data.get('username', '').strip().lower()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({
                'success': False,
                'error': 'Usuário e senha são obrigatórios'
            }), 400
        
        user = authenticate_user(username, password)
        
        if not user:
            logger.warning(f"Tentativa de login falhou para usuário: {username}")
            return jsonify({
                'success': False,
                'error': 'Usuário ou senha inválidos'
            }), 401
        
        token = generate_token(user)
        
        logger.info(f"Login bem-sucedido: {user['name']} ({username})")
        
        return jsonify({
            'success': True,
            'token': token,
            'user': {
                'username': user['username'],
                'name': user['name'],
                'role': user['role']
            }
        })
        
    except Exception as e:
        logger.error(f"Erro no login: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Erro interno no servidor'
        }), 500


@app.route('/api/auth/verify', methods=['GET'])
@token_required
def verify():
    """Verifica se token é válido"""
    return jsonify({
        'success': True,
        'user': request.current_user
    })


# ==================== ROTAS DA API (PROTEGIDAS) ====================

@app.route('/')
def serve_frontend():
    """Serve o frontend React"""
    return send_from_directory(app.static_folder, 'index.html')


@app.route('/api/health', methods=['GET'])
def health_check():
    """Verifica se o backend está rodando"""
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'switch': SWITCH_CONFIG['host']
    })

@app.route('/api/switch/save', methods=['POST'])
@token_required
@with_switch_connection
def save_switch_config(conn):
    """Salva a configuração atual no switch (VRP Huawei)"""
    try:
        logger.info(f"[{request.current_user['name']}] Salvando configuração do switch...")

        # 1. Garante que está fora do system-view
        conn.execute_command('return', wait_time=1)

        # 2. Executa save no nível correto
        conn.execute_command('save', wait_time=1)

        # 3. Confirma (não há mais interações após isso)
        output = conn.execute_command('Y', wait_time=5)

        if not output:
            return jsonify({
                'success': False,
                'error': 'Sem resposta após confirmação do save'
            }), 500

        logger.info("Configuração salva com sucesso no switch")

        return jsonify({
            'success': True,
            'message': 'Configuração salva com sucesso no switch'
        })

    except Exception as e:
        logger.error(f"Erro ao salvar configuração do switch: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/dashboard', methods=['GET'])
@token_required
@with_switch_connection
def dashboard(conn):
    """
    Dashboard geral dos APs
    Retorna estatísticas consolidadas para o frontend
    """
    try:
        logger.info(f"[{request.current_user['name']}] Carregando dashboard...")

        # Obtém todos os APs
        output = conn.execute_command('display ap all', wait_time=1)

        if not output:
            return jsonify({'success': False, 'error': 'Falha ao obter APs'}), 500

        aps = parse_ap_list(output)

        total_aps = len(aps)
        online = 0
        offline = 0
        idle = 0
        default_aps = 0
        groups_count = {}

        for ap in aps:
            # Status
            state = ap.get('state', '').lower()
            if state == 'online':
                online += 1
            elif state == 'offline':
                offline += 1
            elif state == 'idle':
                idle += 1

            # Grupos
            group = ap.get('group', 'default')
            groups_count[group] = groups_count.get(group, 0) + 1

            if group == 'default':
                default_aps += 1

        groups = [
            {'name': g, 'count': c}
            for g, c in groups_count.items()
        ]

        return jsonify({
            'total_aps': total_aps,
            'online': online,
            'offline': offline,
            'idle': idle,
            'default_aps': default_aps,
            'groups': groups
        })

    except Exception as e:
        logger.error(f"Erro ao gerar dashboard: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Erro ao gerar dashboard'
        }), 500


@app.route('/api/groups', methods=['GET'])
@token_required
@with_switch_connection
def list_groups(conn):
    """Lista todos os grupos de APs"""
    try:
        logger.info(f"[{request.current_user['name']}] Listando grupos...")
        
        output = conn.execute_command('display ap-group all', wait_time=2)
        
        if not output:
            return jsonify({'success': False, 'error': 'Falha ao obter grupos'}), 500
        
        groups, total_aps = parse_ap_groups(output)
        
        return jsonify({
            'success': True,
            'data': groups,
            'total_aps': total_aps
        })
        
    except Exception as e:
        logger.error(f"Erro ao listar grupos: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/aps', methods=['GET'])
@token_required
@with_switch_connection
def list_all_aps(conn):
    """Lista todos os APs"""
    try:
        group = request.args.get('group')
        
        if group:
            logger.info(f"[{request.current_user['name']}] Listando APs do grupo '{group}'...")
            output = conn.execute_command(f'display ap ap-group {group}', wait_time=1)
        else:
            logger.info(f"[{request.current_user['name']}] Listando todos os APs...")
            output = conn.execute_command('display ap all', wait_time=1)
        
        if not output:
            return jsonify({'success': False, 'error': 'Falha ao obter APs'}), 500
        
        aps = parse_ap_list(output)
        
        search = request.args.get('search', '').lower()
        if search:
            aps = [ap for ap in aps if 
                   search in ap['mac'].lower() or
                   search in ap['name'].lower() or
                   (ap.get('serial') and search in ap['serial'].lower())]
        
        return jsonify({
            'success': True,
            'data': aps,
            'count': len(aps)
        })
        
    except Exception as e:
        logger.error(f"Erro ao listar APs: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/aps/<ap_id>', methods=['GET'])
@token_required
@with_switch_connection
def get_ap_details(conn, ap_id):
    """Obtém detalhes completos de um AP"""
    try:
        logger.info(f"[{request.current_user['name']}] Obtendo detalhes do AP ID {ap_id}...")
        
        config_output = conn.execute_command(f'display ap config-info ap-id {ap_id}', wait_time=1)
        run_output = conn.execute_command(f'display ap run-info ap-id {ap_id}', wait_time=1)
        
        if not config_output or 'Error' in config_output:
            return jsonify({'success': False, 'error': 'AP não encontrado'}), 404
        
        config = parse_ap_config(config_output)
        run_info = parse_ap_run_info(run_output) if run_output else {}
        
        ap_data = {
            **config['basic'],
            **run_info,
            'radios': config['radios']
        }
        
        return jsonify({
            'success': True,
            'data': ap_data
        })
        
    except Exception as e:
        logger.error(f"Erro ao obter detalhes do AP {ap_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/aps/<ap_id>/stations', methods=['GET'])
@token_required
@with_switch_connection
def get_ap_stations(conn, ap_id):
    """Obtém clientes conectados em um AP"""
    try:
        output = conn.execute_command(f'display station ap-id {ap_id}', wait_time=1)
        
        if not output:
            return jsonify({'success': False, 'error': 'Falha ao obter clientes'}), 500
        
        stations = parse_stations(output)
        
        return jsonify({
            'success': True,
            'data': stations,
            'count': len(stations)
        })
        
    except Exception as e:
        logger.error(f"Erro ao obter clientes do AP {ap_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/aps/<ap_id>/move', methods=['POST'])
@token_required
@with_switch_connection
def move_ap(conn, ap_id):
    """Move AP para outro grupo"""
    try:
        data = request.json
        new_group = data.get('group')
        
        if not new_group:
            return jsonify({'success': False, 'error': 'Grupo não especificado'}), 400
        
        logger.info(f"[{request.current_user['name']}] Movendo AP ID {ap_id} para grupo '{new_group}'...")
        
        commands = [
            'system-view',
            'wlan',
            f'ap-id {ap_id}',
            f'ap-group {new_group}\nY',
            'quit',
            'quit'
        ]
        
        outputs = conn.execute_commands(commands, wait_time=0.5)
        full_output = '\n'.join([o for o in outputs if o])
        
        if 'Error' in full_output or 'failed' in full_output.lower():
            return jsonify({
                'success': False,
                'error': 'Erro ao mover AP. Verifique se o grupo existe.'
            }), 500
        
        log_entry = f"{datetime.now().isoformat()} | Usuário: {request.current_user['name']} | Ação: Mover AP | ID: {ap_id} | Novo Grupo: {new_group}"
        logger.info(log_entry)
        
        with open('ap_actions_audit.log', 'a') as f:
            f.write(log_entry + '\n')
        
        return jsonify({
            'success': True,
            'message': f'AP movido para o grupo "{new_group}" com sucesso!'
        })
        
    except Exception as e:
        logger.error(f"Erro ao mover AP {ap_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/aps/<ap_id>/rename', methods=['POST'])
@token_required
@with_switch_connection
def rename_ap(conn, ap_id):
    """Renomeia um AP"""
    try:
        data = request.json
        new_name = data.get('name')
        
        if not new_name:
            return jsonify({'success': False, 'error': 'Nome não especificado'}), 400
        
        logger.info(f"[{request.current_user['name']}] Renomeando AP ID {ap_id} para '{new_name}'...")
        
        commands = [
            'system-view',
            'wlan',
            f'ap-id {ap_id}',
            f'ap-name {new_name}\nY',
            'quit',
            'quit'
        ]
        
        outputs = conn.execute_commands(commands, wait_time=1)
        full_output = '\n'.join([o for o in outputs if o])

        logger.info(f"Output do switch ao renomear: {full_output}")

        if 'Error' in full_output or 'failed' in full_output.lower():
            return jsonify({
                'success': False,
                'error': 'Erro ao renomear AP.'
            }), 500
        
        log_entry = f"{datetime.now().isoformat()} | Usuário: {request.current_user['name']} | Ação: Renomear AP | ID: {ap_id} | Novo Nome: {new_name}"
        logger.info(log_entry)
        
        with open('ap_actions_audit.log', 'a') as f:
            f.write(log_entry + '\n')
        
        return jsonify({
            'success': True,
            'message': f'AP renomeado para "{new_name}" com sucesso!'
        })
        
    except Exception as e:
        logger.error(f"Erro ao renomear AP {ap_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/aps/<ap_id>/remove-group', methods=['POST'])
@token_required
@with_switch_connection
def remove_from_group(conn, ap_id):
    """Remove AP do grupo (volta para default)"""
    try:
        logger.info(f"[{request.current_user['name']}] Removendo AP ID {ap_id} do grupo...")
        
        commands = [
            'system-view',
            'wlan',
            f'ap-id {ap_id}',
            'undo ap-group',
            'Y',
            'quit',
            'quit'
        ]
        
        outputs = conn.execute_commands(commands, wait_time=0.5)
        full_output = '\n'.join([o for o in outputs if o])
        
        if 'Error' in full_output or 'failed' in full_output.lower():
            return jsonify({
                'success': False,
                'error': 'Erro ao remover AP do grupo.'
            }), 500
        
        log_entry = f"{datetime.now().isoformat()} | Usuário: {request.current_user['name']} | Ação: Remover de Grupo | ID: {ap_id}"
        logger.info(log_entry)
        
        with open('ap_actions_audit.log', 'a') as f:
            f.write(log_entry + '\n')
        
        return jsonify({
            'success': True,
            'message': 'AP removido do grupo (movido para default) com sucesso!'
        })
        
    except Exception as e:
        logger.error(f"Erro ao remover AP {ap_id} do grupo: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== INICIALIZAÇÃO ====================

if __name__ == '__main__':
    logger.info("=" * 70)
    logger.info("Sistema de Gerenciamento de APs - Huawei S6730")
    logger.info("Com Autenticação JWT")
    logger.info("=" * 70)
    logger.info(f"Switch: {SWITCH_CONFIG['host']}")
    logger.info(f"Usuário do Switch: {SWITCH_CONFIG['username']}")
    logger.info("=" * 70)
    
    # Inicializa arquivo de usuários se não existir
    users = load_users()
    logger.info(f"Usuários carregados: {len(users)}")
    
    # Em produção, use Gunicorn
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False
    )
