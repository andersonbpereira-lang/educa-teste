import os
import sqlite3
import secrets
import hashlib
import smtplib
import json
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024
origins = [x.strip() for x in os.getenv('EDUCA_ALLOWED_ORIGINS', '*').split(',') if x.strip()]
CORS(app, resources={r'/api/*': {'origins': origins}})

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.getenv('EDUCA_DB', os.path.join(BASE_DIR, 'educa.db'))
SECRET = os.getenv('EDUCA_SERVER_SECRET', 'CHANGE-ME-IN-PRODUCTION')
ENVIRONMENT = os.getenv('EDUCA_ENV', 'development').strip().lower()
CODE_TTL_MIN = 10
TOKEN_TTL_DAYS = 30

SUBJECTS = {
    'Matemática', 'Português', 'Ciências', 'História',
    'Geografia', 'Inglês', 'Informática', 'Artes'
}


@app.after_request
def security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    if request.path.startswith('/api/'):
        response.headers.setdefault('Cache-Control', 'no-store')
    if ENVIRONMENT == 'production':
        response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    return response


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.isoformat()


def init_db():
    conn = db()
    conn.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        verified INTEGER NOT NULL DEFAULT 0,
        progress TEXT,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS verification_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS password_reset_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE INDEX IF NOT EXISTS idx_codes_email ON verification_codes(email);
    CREATE INDEX IF NOT EXISTS idx_reset_email ON password_reset_codes(email);
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    ''')
    conn.commit()
    conn.close()


def normalize_email(email):
    return email.strip().lower()


def valid_email(email):
    return '@' in email and '.' in email.split('@')[-1] and len(email) <= 160


def code_hash(code):
    return hashlib.sha256((SECRET + ':' + code).encode()).hexdigest()


def token_hash(token):
    return hashlib.sha256((SECRET + ':' + token).encode()).hexdigest()


def smtp_configured():
    return all(os.getenv(k) for k in ('SMTP_HOST', 'SMTP_USER', 'SMTP_PASSWORD', 'SMTP_FROM'))


def send_email(to_email, subject, body):
    host = os.getenv('SMTP_HOST')
    port = int(os.getenv('SMTP_PORT', '587'))
    sender = os.getenv('SMTP_FROM') or os.getenv('SMTP_USER')
    user = os.getenv('SMTP_USER')
    password = os.getenv('SMTP_PASSWORD')
    if not host or not sender or not user or not password:
        raise RuntimeError('SMTP não configurado. Defina SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD e SMTP_FROM.')
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = to_email
    msg.set_content(body)
    with smtplib.SMTP(host, port, timeout=20) as smtp:
        if os.getenv('SMTP_TLS', '1') != '0':
            smtp.starttls()
        smtp.login(user, password)
        smtp.send_message(msg)


def create_code(table, email, username=None, subject='Seu código — Educa-', purpose='confirmation'):
    conn = db()
    recent = conn.execute(
        f'SELECT created_at FROM {table} WHERE email=? ORDER BY id DESC LIMIT 1',
        (email,)
    ).fetchone()
    if recent:
        try:
            if now() - datetime.fromisoformat(recent['created_at']) < timedelta(seconds=60):
                conn.close()
                raise ValueError('Aguarde 60 segundos antes de pedir outro código.')
        except ValueError:
            conn.close()
            raise

    code = f'{secrets.randbelow(1000000):06d}'
    conn.execute(f'UPDATE {table} SET used=1 WHERE email=? AND used=0', (email,))
    conn.execute(
        f'INSERT INTO {table}(email,code_hash,expires_at,created_at) VALUES(?,?,?,?)',
        (email, code_hash(code), iso(now() + timedelta(minutes=CODE_TTL_MIN)), iso(now()))
    )
    conn.commit()
    conn.close()

    if purpose == 'confirmation':
        body = (
            f'Olá, {username}!\n\n'
            f'Seu código de confirmação do Educa- é: {code}\n\n'
            f'Esse código expira em {CODE_TTL_MIN} minutos.\n'
            'Se você não criou essa conta, ignore este e-mail.\n\nEduca-'
        )
    else:
        body = (
            'Olá!\n\n'
            f'Seu código para redefinir a senha do Educa- é: {code}\n\n'
            f'Esse código expira em {CODE_TTL_MIN} minutos.\n'
            'Se você não solicitou a redefinição, ignore este e-mail.\n\nEduca-'
        )
    try:
        send_email(email, subject, body)
    except Exception:
        conn = db()
        conn.execute(f'UPDATE {table} SET used=1 WHERE email=? AND used=0', (email,))
        conn.commit()
        conn.close()
        raise


def auth_user():
    token = request.headers.get('Authorization', '').replace('Bearer ', '').strip()
    if not token:
        return None
    conn = db()
    row = conn.execute(
        '''SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id
           WHERE s.token_hash=? AND s.expires_at>? AND u.verified=1''',
        (token_hash(token), iso(now()))
    ).fetchone()
    conn.close()
    return row


def new_session(user_id):
    token = secrets.token_urlsafe(40)
    conn = db()
    conn.execute(
        'INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)',
        (token_hash(token), user_id, iso(now() + timedelta(days=TOKEN_TTL_DAYS)))
    )
    conn.commit()
    conn.close()
    return token


@app.get('/api/health')
def health():
    db_ok = False
    try:
        conn = db()
        conn.execute('SELECT 1').fetchone()
        conn.close()
        db_ok = True
    except Exception:
        db_ok = False
    return jsonify({
        'ok': db_ok,
        'service': 'Educa- backend',
        'environment': ENVIRONMENT,
        'database': db_ok,
        'email_verification': smtp_configured(),
        'professor_ia': bool(os.getenv('OPENAI_API_KEY')),
        'password_recovery': smtp_configured(),
        'https_required_for_production': ENVIRONMENT == 'production'
    })


@app.post('/api/auth/register')
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get('username', '')).strip()
    email = normalize_email(str(data.get('email', '')))
    password = str(data.get('password', ''))
    if len(username) < 2 or len(username) > 20:
        return jsonify(error='O usuário deve ter entre 2 e 20 caracteres.'), 400
    if not valid_email(email):
        return jsonify(error='Digite um e-mail válido.'), 400
    if len(password) < 8:
        return jsonify(error='A senha precisa ter pelo menos 8 caracteres.'), 400
    if not smtp_configured():
        return jsonify(error='O envio de e-mail ainda não está configurado no servidor.'), 503

    conn = db()
    exists = conn.execute(
        'SELECT id FROM users WHERE username=? OR email=?', (username, email)
    ).fetchone()
    if exists:
        conn.close()
        return jsonify(error='Esse usuário ou e-mail já está cadastrado.'), 409
    salt = secrets.token_urlsafe(16)
    conn.execute(
        'INSERT INTO users(username,email,password_hash,salt,verified,created_at) VALUES(?,?,?,?,0,?)',
        (username, email, generate_password_hash(password), salt, 0, iso(now()))
    )
    conn.commit()
    conn.close()
    try:
        create_code('verification_codes', email, username, 'Seu código de confirmação — Educa-', 'confirmation')
    except Exception as exc:
        conn = db()
        conn.execute('DELETE FROM users WHERE email=?', (email,))
        conn.commit()
        conn.close()
        return jsonify(error=f'Não foi possível enviar o código: {exc}'), 502
    return jsonify(ok=True, message='Código enviado para seu e-mail.', email=email)


@app.post('/api/auth/resend')
def resend():
    data = request.get_json(silent=True) or {}
    email = normalize_email(str(data.get('email', '')))
    conn = db()
    user = conn.execute('SELECT username,verified FROM users WHERE email=?', (email,)).fetchone()
    conn.close()
    if not user:
        return jsonify(error='Conta não encontrada.'), 404
    if user['verified']:
        return jsonify(error='Esse e-mail já está confirmado.'), 400
    try:
        create_code('verification_codes', email, user['username'], 'Seu novo código — Educa-', 'confirmation')
    except Exception as exc:
        return jsonify(error=str(exc)), 429
    return jsonify(ok=True, message='Novo código enviado.')


@app.post('/api/auth/verify')
def verify():
    data = request.get_json(silent=True) or {}
    email = normalize_email(str(data.get('email', '')))
    code = str(data.get('code', '')).strip()
    conn = db()
    user = conn.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
    row = conn.execute(
        'SELECT * FROM verification_codes WHERE email=? AND used=0 ORDER BY id DESC LIMIT 1',
        (email,)
    ).fetchone()
    if not user or not row:
        conn.close()
        return jsonify(error='Código inválido ou expirado.'), 400
    if datetime.fromisoformat(row['expires_at']) < now() or code_hash(code) != row['code_hash']:
        conn.close()
        return jsonify(error='Código inválido ou expirado.'), 400
    conn.execute('UPDATE verification_codes SET used=1 WHERE id=?', (row['id'],))
    conn.execute('UPDATE users SET verified=1 WHERE id=?', (user['id'],))
    conn.commit()
    conn.close()
    token = new_session(user['id'])
    return jsonify(ok=True, token=token, username=user['username'], email=user['email'], salt=user['salt'], progress=user['progress'])


@app.post('/api/auth/login')
def login():
    data = request.get_json(silent=True) or {}
    identifier = str(data.get('identifier', '')).strip()
    password = str(data.get('password', ''))
    conn = db()
    user = conn.execute(
        'SELECT * FROM users WHERE lower(email)=lower(?) OR lower(username)=lower(?)',
        (identifier, identifier)
    ).fetchone()
    conn.close()
    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify(error='E-mail/usuário ou senha incorretos.'), 401
    if not user['verified']:
        return jsonify(error='CONFIRM_EMAIL', email=user['email']), 403
    token = new_session(user['id'])
    return jsonify(ok=True, token=token, username=user['username'], email=user['email'], salt=user['salt'], progress=user['progress'])


@app.post('/api/auth/forgot-password')
def forgot_password():
    data = request.get_json(silent=True) or {}
    email = normalize_email(str(data.get('email', '')))
    if not valid_email(email):
        return jsonify(error='Digite um e-mail válido.'), 400
    conn = db()
    user = conn.execute('SELECT username,verified FROM users WHERE email=?', (email,)).fetchone()
    conn.close()
    if user and user['verified']:
        if not smtp_configured():
            return jsonify(error='O envio de e-mail ainda não está configurado no servidor.'), 503
        try:
            create_code('password_reset_codes', email, user['username'], 'Redefinição de senha — Educa-', 'reset')
        except ValueError as exc:
            return jsonify(error=str(exc)), 429
        except Exception as exc:
            return jsonify(error=f'Não foi possível enviar o código: {exc}'), 502
    return jsonify(ok=True, message='Se existir uma conta confirmada com esse e-mail, um código será enviado.')


@app.post('/api/auth/reset-password')
def reset_password():
    data = request.get_json(silent=True) or {}
    email = normalize_email(str(data.get('email', '')))
    code = str(data.get('code', '')).strip()
    new_password = str(data.get('password', ''))
    if not valid_email(email) or not code.isdigit() or len(code) != 6:
        return jsonify(error='E-mail ou código inválido.'), 400
    if len(new_password) < 8:
        return jsonify(error='A nova senha precisa ter pelo menos 8 caracteres.'), 400
    conn = db()
    user = conn.execute('SELECT * FROM users WHERE email=? AND verified=1', (email,)).fetchone()
    row = conn.execute(
        'SELECT * FROM password_reset_codes WHERE email=? AND used=0 ORDER BY id DESC LIMIT 1',
        (email,)
    ).fetchone()
    if not user or not row:
        conn.close()
        return jsonify(error='Código inválido ou expirado.'), 400
    if datetime.fromisoformat(row['expires_at']) < now() or code_hash(code) != row['code_hash']:
        conn.close()
        return jsonify(error='Código inválido ou expirado.'), 400
    new_salt = secrets.token_urlsafe(16)
    # O progresso antigo é mantido no banco, mas fica inacessível se o usuário
    # perdeu a senha anterior porque o blob foi cifrado no navegador com ela.
    conn.execute('UPDATE password_reset_codes SET used=1 WHERE id=?', (row['id'],))
    conn.execute(
        'UPDATE users SET password_hash=?,salt=?,progress=NULL WHERE id=?',
        (generate_password_hash(new_password), new_salt, user['id'])
    )
    conn.execute('DELETE FROM sessions WHERE user_id=?', (user['id'],))
    conn.commit()
    conn.close()
    token = new_session(user['id'])
    return jsonify(ok=True, token=token, username=user['username'], email=user['email'], salt=new_salt, progress=None)


@app.post('/api/auth/logout')
def logout():
    token = request.headers.get('Authorization', '').replace('Bearer ', '').strip()
    if token:
        conn = db()
        conn.execute('DELETE FROM sessions WHERE token_hash=?', (token_hash(token),))
        conn.commit()
        conn.close()
    return jsonify(ok=True)


@app.get('/api/progress')
def get_progress():
    user = auth_user()
    if not user:
        return jsonify(error='Não autenticado.'), 401
    return jsonify(progress=user['progress'])


@app.put('/api/progress')
def put_progress():
    user = auth_user()
    if not user:
        return jsonify(error='Não autenticado.'), 401
    data = request.get_json(silent=True) or {}
    blob = data.get('progress')
    if not isinstance(blob, dict) or 'iv' not in blob or 'data' not in blob:
        return jsonify(error='Dados de progresso inválidos.'), 400
    conn = db()
    conn.execute(
        'UPDATE users SET progress=? WHERE id=?',
        (json.dumps(blob, separators=(',', ':')), user['id'])
    )
    conn.commit()
    conn.close()
    return jsonify(ok=True)


def professor_explain_prompt(subject, question):
    return f"""Você é o Professor IA do Educa-, uma plataforma educacional para estudantes.
Matéria: {subject}
Pergunta do estudante: {question}

Explique de maneira simples, correta e apropriada para estudantes.
Estruture a resposta com: explicação principal, exemplo simples, dica para lembrar e uma pergunta curta para conferir se a pessoa entendeu.
Não invente fatos. Se a pergunta estiver ambígua, explique a interpretação mais escolar e peça esclarecimento quando necessário.
Não inclua conteúdo sexual, perigoso ou impróprio para menores."""


@app.post('/api/professor/explain')
def professor_explain():
    user = auth_user()
    if not user:
        return jsonify(error='Faça login para usar o Professor IA.'), 401
    data = request.get_json(silent=True) or {}
    subject = str(data.get('subject', '')).strip()
    question = str(data.get('question', '')).strip()
    if subject not in SUBJECTS:
        return jsonify(error='Matéria inválida.'), 400
    if len(question) < 3 or len(question) > 500:
        return jsonify(error='Digite uma pergunta entre 3 e 500 caracteres.'), 400
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        return jsonify(error='O Professor IA ainda não está configurado no servidor.'), 503
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        response = client.responses.create(
            model=os.getenv('OPENAI_MODEL', 'gpt-5.6-luna'),
            input=professor_explain_prompt(subject, question),
            store=False
        )
        answer = (response.output_text or '').strip()
        if not answer:
            return jsonify(error='O professor não conseguiu responder agora.'), 502
        return jsonify(ok=True, answer=answer)
    except Exception as exc:
        return jsonify(error=f'Não foi possível consultar o Professor IA: {exc}'), 502


def professor_curriculum_prompt(subject, topic, difficulty):
    return f"""Você é o Professor IA do Educa-, uma plataforma educacional para estudantes.
Crie uma trilha completa de estudo para a matéria "{subject}" sobre o conteúdo "{topic}".

A trilha DEVE ter exatamente 25 fases. Cada fase DEVE ter exatamente 5 questões: total de 125 questões.
Dificuldade geral: {difficulty}. A dificuldade deve aumentar gradualmente das fases 1-5 até 21-25.

REGRAS MUITO IMPORTANTES:
- As 125 questões precisam ser realmente diferentes entre si. Não faça a mesma pergunta trocando números, nomes, sinônimos ou a ordem das alternativas.
- Cada fase deve aprofundar o conteúdo, mantendo foco na matéria escolhida.
- Distribua subtemas diferentes quando o conteúdo permitir.
- Cada questão deve ter exatamente 4 alternativas diferentes.
- "correct" deve ser exatamente uma das 4 alternativas.
- Inclua uma explicação curta e correta para cada resposta.
- Não invente fatos. Se o tópico for amplo, organize uma progressão escolar coerente.
- Linguagem clara e apropriada para estudantes.
- Não inclua conteúdo sexual, perigoso ou impróprio para menores.
- Retorne somente o objeto no formato solicitado."""


@app.post('/api/professor/curriculum')
def professor_curriculum():
    user = auth_user()
    if not user:
        return jsonify(error='Faça login para usar o Professor IA.'), 401
    data = request.get_json(silent=True) or {}
    subject = str(data.get('subject', '')).strip()
    topic = str(data.get('topic', '')).strip()
    difficulty = str(data.get('difficulty', 'medio')).strip()
    if subject not in SUBJECTS:
        return jsonify(error='Matéria inválida.'), 400
    if len(topic) < 3 or len(topic) > 120:
        return jsonify(error='Digite um conteúdo entre 3 e 120 caracteres.'), 400
    if difficulty not in {'facil', 'medio', 'dificil', 'desafio'}:
        return jsonify(error='Dificuldade inválida.'), 400
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        return jsonify(error='O Professor IA ainda não está configurado no servidor.'), 503
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        question_schema = {
            'type': 'object', 'properties': {
                'question': {'type': 'string'},
                'answers': {'type': 'array', 'minItems': 4, 'maxItems': 4, 'items': {'type': 'string'}},
                'correct': {'type': 'string'}, 'topic': {'type': 'string'}, 'explanation': {'type': 'string'}
            }, 'required': ['question','answers','correct','topic','explanation'], 'additionalProperties': False
        }
        phase_schema = {
            'type': 'object', 'properties': {
                'phase': {'type': 'integer'}, 'title': {'type': 'string'}, 'focus': {'type': 'string'},
                'questions': {'type': 'array', 'minItems': 5, 'maxItems': 5, 'items': question_schema}
            }, 'required': ['phase','title','focus','questions'], 'additionalProperties': False
        }
        schema = {
            'type': 'object', 'properties': {
                'subject': {'type': 'string'}, 'topic': {'type': 'string'},
                'phases': {'type': 'array', 'minItems': 25, 'maxItems': 25, 'items': phase_schema}
            }, 'required': ['subject','topic','phases'], 'additionalProperties': False
        }
        response = client.responses.create(
            model=os.getenv('OPENAI_MODEL', 'gpt-5.6-luna'),
            input=professor_curriculum_prompt(subject, topic, difficulty),
            store=False,
            text={'format': {'type': 'json_schema', 'name': 'educa_curriculum', 'strict': True, 'schema': schema}}
        )
        payload = json.loads(response.output_text)
        phases = payload.get('phases', [])
        clean_phases, seen_questions = [], set()
        for idx, phase in enumerate(phases[:25], start=1):
            qs=[]
            for q in phase.get('questions', []):
                answers=[str(a).strip() for a in q.get('answers', [])]
                question=str(q.get('question','')).strip(); correct=str(q.get('correct','')).strip()
                normalized=' '.join(question.lower().split())
                if not question or normalized in seen_questions: continue
                if len(answers)!=4 or len(set(a.lower() for a in answers))!=4 or correct not in answers: continue
                seen_questions.add(normalized)
                qs.append({'question':question,'answers':answers,'correct':correct,'topic':str(q.get('topic') or topic).strip(),'explanation':str(q.get('explanation') or 'Revise este conteúdo e tente novamente.').strip()})
            if len(qs)==5:
                clean_phases.append({'phase':idx,'title':str(phase.get('title') or f'Fase {idx}').strip(),'focus':str(phase.get('focus') or topic).strip(),'questions':qs})
        if len(clean_phases)!=25:
            return jsonify(error='A IA não conseguiu montar 25 fases com 125 perguntas diferentes. Tente um conteúdo mais específico.'), 502
        return jsonify(ok=True, subject=subject, topic=topic, difficulty=difficulty, phases=clean_phases)
    except Exception as exc:
        return jsonify(error=f'Não foi possível criar a trilha com o Professor IA: {exc}'), 502


def professor_prompt(subject, topic, difficulty, count):
    return f'''Você é o Professor IA do Educa-, uma plataforma educacional para estudantes.
Crie {count} questões de múltipla escolha sobre a matéria "{subject}" e o conteúdo "{topic}".
Dificuldade: {difficulty}.

Regras obrigatórias:
- Gere questões realmente diferentes entre si; não apenas troque números ou sinônimos.
- Adeque a linguagem ao estudante e explique o raciocínio de forma clara.
- Cada questão deve ter exatamente 4 alternativas diferentes.
- "correct" deve ser exatamente uma das alternativas.
- Não invente fatos. Se o tópico for ambíguo, faça uma pergunta escolar segura e factual.
- Não inclua conteúdo sexual, perigoso ou impróprio para menores.
- Retorne somente o objeto no formato solicitado.'''


@app.post('/api/professor/generate')
def professor_generate():
    user = auth_user()
    if not user:
        return jsonify(error='Faça login para usar o Professor IA.'), 401
    data = request.get_json(silent=True) or {}
    subject = str(data.get('subject', '')).strip()
    topic = str(data.get('topic', '')).strip()
    difficulty = str(data.get('difficulty', 'medio')).strip()
    try:
        count = int(data.get('count', 5))
    except (TypeError, ValueError):
        count = 5
    if subject not in SUBJECTS:
        return jsonify(error='Matéria inválida.'), 400
    if len(topic) < 3 or len(topic) > 120:
        return jsonify(error='Digite um conteúdo entre 3 e 120 caracteres.'), 400
    if difficulty not in {'facil', 'medio', 'dificil', 'desafio'}:
        return jsonify(error='Dificuldade inválida.'), 400
    count = max(5, min(count, 10))

    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        return jsonify(error='O Professor IA ainda não está configurado no servidor.'), 503

    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        schema = {
            'type': 'object',
            'properties': {
                'questions': {
                    'type': 'array',
                    'minItems': count,
                    'maxItems': count,
                    'items': {
                        'type': 'object',
                        'properties': {
                            'question': {'type': 'string'},
                            'answers': {'type': 'array', 'minItems': 4, 'maxItems': 4, 'items': {'type': 'string'}},
                            'correct': {'type': 'string'},
                            'topic': {'type': 'string'},
                            'explanation': {'type': 'string'}
                        },
                        'required': ['question', 'answers', 'correct', 'topic', 'explanation'],
                        'additionalProperties': False
                    }
                }
            },
            'required': ['questions'],
            'additionalProperties': False
        }
        response = client.responses.create(
            model=os.getenv('OPENAI_MODEL', 'gpt-5.6-luna'),
            input=professor_prompt(subject, topic, difficulty, count),
            store=False,
            text={'format': {'type': 'json_schema', 'name': 'educa_questions', 'strict': True, 'schema': schema}}
        )
        raw = response.output_text
        payload = json.loads(raw)
        questions = payload.get('questions', [])
        clean = []
        for q in questions:
            answers = [str(a).strip() for a in q.get('answers', [])]
            correct = str(q.get('correct', '')).strip()
            question = str(q.get('question', '')).strip()
            if len(answers) == 4 and len(set(answers)) == 4 and correct in answers and question:
                clean.append({
                    'question': question,
                    'answers': answers,
                    'correct': correct,
                    'topic': str(q.get('topic') or topic).strip(),
                    'explanation': str(q.get('explanation') or 'Revise este conteúdo e tente novamente.').strip()
                })
        if len(clean) < 5:
            return jsonify(error='A IA não conseguiu gerar perguntas suficientes. Tente outro conteúdo.'), 502
        return jsonify(ok=True, questions=clean[:count])
    except Exception as exc:
        return jsonify(error=f'Não foi possível gerar a missão agora: {exc}'), 502


if ENVIRONMENT == 'production' and SECRET == 'CHANGE-ME-IN-PRODUCTION':
    raise RuntimeError('Defina EDUCA_SERVER_SECRET antes de iniciar o Educa- em produção.')

init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', '5000')), debug=False)
