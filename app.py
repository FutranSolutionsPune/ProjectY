import os, re, secrets, sqlite3, uuid, html
from datetime import datetime, timezone
from pathlib import Path
from functools import wraps
from flask import Flask, g, request, session, redirect, url_for, render_template, flash, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv('DATA_DIR', str(BASE_DIR / 'data')))
UPLOAD_DIR = Path(os.getenv('UPLOAD_DIR', str(DATA_DIR / 'uploads')))
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.getenv('SQLITE_PATH', str(DATA_DIR / 'tickets.db')))
local_secret_path = DATA_DIR / '.secret_key'
if not os.getenv('SECRET_KEY') and not local_secret_path.exists():
    local_secret_path.write_text(secrets.token_hex(48), encoding='utf-8')
app = Flask(__name__)
app.config.update(SECRET_KEY=os.getenv('SECRET_KEY') or local_secret_path.read_text(encoding='utf-8').strip(), MAX_CONTENT_LENGTH=10 * 1024 * 1024, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.getenv('COOKIE_SECURE', '0') == '1', PERMANENT_SESSION_LIFETIME=60*60*8)
ALLOWED_EXTENSIONS = {'png','jpg','jpeg','gif','webp'}
PRIORITIES = ['Low','Medium','High','Critical']
STATUSES = ['Open','In Progress','Resolved','Closed']

SCHEMA = '''
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, full_name TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','engineer','user')), active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS projects(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, description TEXT DEFAULT '', active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tickets(id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_key TEXT UNIQUE, project_id INTEGER NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, priority TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Open', created_by INTEGER NOT NULL, assigned_to INTEGER, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, resolved_at TEXT, closed_at TEXT, FOREIGN KEY(project_id) REFERENCES projects(id), FOREIGN KEY(created_by) REFERENCES users(id), FOREIGN KEY(assigned_to) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER NOT NULL, author_id INTEGER NOT NULL, body_html TEXT NOT NULL, created_at TEXT NOT NULL, event_type TEXT NOT NULL DEFAULT 'comment', FOREIGN KEY(ticket_id) REFERENCES tickets(id), FOREIGN KEY(author_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS attachments(id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER NOT NULL, comment_id INTEGER, original_name TEXT NOT NULL, stored_name TEXT NOT NULL, mime_type TEXT, size_bytes INTEGER NOT NULL, uploaded_by INTEGER NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(ticket_id) REFERENCES tickets(id), FOREIGN KEY(comment_id) REFERENCES comments(id), FOREIGN KEY(uploaded_by) REFERENCES users(id));
CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);
CREATE INDEX IF NOT EXISTS idx_tickets_assignee ON tickets(assigned_to);
CREATE INDEX IF NOT EXISTS idx_comments_ticket ON comments(ticket_id);
'''

def now(): return datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')
def db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=15)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys=ON')
        g.db.execute('PRAGMA journal_mode=WAL')
    return g.db
@app.teardown_appcontext
def close_db(_=None):
    conn = g.pop('db', None)
    if conn is not None: conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    conn.commit(); conn.close()
init_db()

@app.before_request
def csrf_setup():
    if 'csrf_token' not in session: session['csrf_token'] = secrets.token_urlsafe(32)
    if request.method == 'POST':
        token = request.form.get('csrf_token', '')
        if not token or not secrets.compare_digest(token, session.get('csrf_token', '')):
            abort(400, 'Invalid or missing CSRF token. Refresh the page and try again.')

def current_user():
    uid = session.get('user_id')
    if not uid: return None
    return db().execute('SELECT id, username, full_name, role, active FROM users WHERE id=?', (uid,)).fetchone()
@app.context_processor
def inject_globals(): return {'current_user': current_user(), 'csrf_token': session.get('csrf_token',''), 'now_year': datetime.now().year}
def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        u = current_user()
        if not u or not u['active']:
            session.clear(); flash('Please sign in to continue.', 'info'); return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapped
def roles(*allowed):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapped(*args, **kwargs):
            u=current_user()
            if u['role'] not in allowed: abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return decorator

def clean_html(value):
    # Conservative allow-list sanitizer; no scripts, styles, images, links or event attributes.
    value = value or ''
    value = re.sub(r'<(script|style|iframe|object|svg|math)[^>]*>.*?</\1\s*>', '', value, flags=re.I|re.S)
    value = re.sub(r'\s+on[a-z]+\s*=\s*(["\']).*?\1', '', value, flags=re.I|re.S)
    value = re.sub(r'\s+on[a-z]+\s*=\s*[^\s>]+', '', value, flags=re.I)
    value = re.sub(r'javascript\s*:', '', value, flags=re.I)
    allowed = {'p','br','strong','b','em','i','u','ul','ol','li','blockquote','code','pre','h3','h4'}
    def strip_tag(match):
        tag = match.group(1).lower().strip('/').split()[0]
        return match.group(0) if tag in allowed and not re.search(r'\s', match.group(1).strip('/')) else ''
    value = re.sub(r'<([^>]+)>', strip_tag, value)
    return value.strip()[:20000]
def plain_text(value):
    return re.sub(r'<[^>]*>', ' ', clean_html(value)).replace('&nbsp;',' ').strip()
def can_view_ticket(ticket, user):
    if user['role']=='admin': return True
    if user['role']=='engineer': return ticket['assigned_to'] in (None,user['id']) or ticket['status'] in ('Resolved','Closed')
    return ticket['created_by'] == user['id']
def get_ticket(ticket_id):
    return db().execute('''SELECT t.*, p.name project_name, creator.full_name creator_name, creator.username creator_username, assignee.full_name assignee_name
        FROM tickets t JOIN projects p ON p.id=t.project_id JOIN users creator ON creator.id=t.created_by LEFT JOIN users assignee ON assignee.id=t.assigned_to WHERE t.id=?''',(ticket_id,)).fetchone()
def ticket_rows(user, status=None):
    sql='''SELECT t.*, p.name project_name, c.full_name creator_name, a.full_name assignee_name FROM tickets t JOIN projects p ON p.id=t.project_id JOIN users c ON c.id=t.created_by LEFT JOIN users a ON a.id=t.assigned_to WHERE 1=1'''
    args=[]
    if user['role']=='user': sql+=' AND t.created_by=?'; args.append(user['id'])
    elif user['role']=='engineer': sql+=' AND (t.assigned_to=? OR t.assigned_to IS NULL OR t.status IN (\'Resolved\',\'Closed\'))'; args.append(user['id'])
    if status and status!='All': sql+=' AND t.status=?'; args.append(status)
    sql+=' ORDER BY CASE t.priority WHEN \'Critical\' THEN 1 WHEN \'High\' THEN 2 WHEN \'Medium\' THEN 3 ELSE 4 END, t.updated_at DESC'
    return db().execute(sql,args).fetchall()
def log_event(ticket_id, body, event_type='event'):
    db().execute('INSERT INTO comments(ticket_id,author_id,body_html,created_at,event_type) VALUES(?,?,?,?,?)',(ticket_id,current_user()['id'],body,now(),event_type))
def allowed_file(filename): return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS
def save_uploads(ticket_id, comment_id=None):
    saved=[]
    for f in request.files.getlist('screenshots'):
        if not f or not f.filename: continue
        original=secure_filename(f.filename)
        if not original or not allowed_file(original): raise ValueError('Only PNG, JPG, JPEG, GIF, and WEBP screenshots are allowed.')
        data=f.read()
        if not data: continue
        if len(data)>5*1024*1024: raise ValueError('Each screenshot must be 5 MB or smaller.')
        # Check file signature instead of trusting the supplied content type.
        signatures = (data.startswith(b'\x89PNG\r\n\x1a\n'), data.startswith(b'\xff\xd8\xff'), data.startswith((b'GIF87a',b'GIF89a')), data.startswith(b'RIFF') and data[8:12]==b'WEBP')
        if not any(signatures): raise ValueError(f'{original} does not look like a supported image file.')
        stored=f'{uuid.uuid4().hex}.{original.rsplit(".",1)[1].lower()}'
        (UPLOAD_DIR/stored).write_bytes(data)
        db().execute('INSERT INTO attachments(ticket_id,comment_id,original_name,stored_name,mime_type,size_bytes,uploaded_by,created_at) VALUES(?,?,?,?,?,?,?,?)',(ticket_id,comment_id,original,f'{ticket_id}/{stored}',f.mimetype,len(data),current_user()['id'],now()))
        saved.append(stored)
    return saved

def get_attachments(ticket_id): return db().execute('SELECT a.*,u.full_name uploader_name FROM attachments a JOIN users u ON u.id=a.uploaded_by WHERE ticket_id=? ORDER BY id',(ticket_id,)).fetchall()
def get_comments(ticket_id): return db().execute('SELECT c.*,u.full_name author_name,u.role author_role FROM comments c JOIN users u ON u.id=c.author_id WHERE c.ticket_id=? ORDER BY c.id',(ticket_id,)).fetchall()

@app.route('/')
def index():
    u=current_user()
    if not u: return redirect(url_for('login'))
    if u['role']=='admin': return redirect(url_for('admin_dashboard'))
    return redirect(url_for('dashboard'))

@app.route('/setup', methods=['GET','POST'])
def setup():
    count=db().execute("SELECT COUNT(*) n FROM users WHERE role='admin'").fetchone()['n']
    if count: return redirect(url_for('login'))
    if request.method=='POST':
        username=request.form.get('username','').strip().lower(); full=request.form.get('full_name','').strip(); password=request.form.get('password',''); confirm=request.form.get('confirm_password','')
        if not re.fullmatch(r'[a-z0-9._-]{3,40}',username): flash('Username must be 3–40 characters (letters, numbers, dot, underscore, hyphen).','error')
        elif len(full)<2 or len(full)>100: flash('Enter your full name.','error')
        elif len(password)<12: flash('Use a password with at least 12 characters.','error')
        elif password!=confirm: flash('Passwords do not match.','error')
        else:
            db().execute('INSERT INTO users(username,full_name,password_hash,role,created_at) VALUES(?,?,?,?,?)',(username,full,generate_password_hash(password), 'admin',now())); db().commit()
            flash('Administrator created. Sign in to configure your helpdesk.','success'); return redirect(url_for('login'))
    return render_template('setup.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if current_user(): return redirect(url_for('index'))
    if request.method=='POST':
        username=request.form.get('username','').strip().lower(); password=request.form.get('password','')
        user=db().execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
        if user and user['active'] and check_password_hash(user['password_hash'],password):
            session.clear(); session['user_id']=user['id']; session['csrf_token']=secrets.token_urlsafe(32); session.permanent=True
            flash(f'Welcome back, {user["full_name"].split()[0]}.','success'); return redirect(url_for('index'))
        flash('Those credentials did not match an active account.','error')
    return render_template('login.html')
@app.route('/logout',methods=['POST'])
@login_required
def logout(): session.clear(); return redirect(url_for('login'))

@app.route('/dashboard')
@roles('user','engineer')
def dashboard():
    u=current_user(); status=request.args.get('status','All')
    rows=ticket_rows(u,status)
    if u['role']=='engineer':
        stats={r['status']:r['n'] for r in db().execute('SELECT status,COUNT(*) n FROM tickets WHERE assigned_to=? GROUP BY status',(u['id'],)).fetchall()}
        stats['Unassigned']=db().execute("SELECT COUNT(*) n FROM tickets WHERE assigned_to IS NULL AND status='Open'").fetchone()['n']
    else: stats={r['status']:r['n'] for r in db().execute('SELECT status,COUNT(*) n FROM tickets WHERE created_by=? GROUP BY status',(u['id'],)).fetchall()}
    projects=db().execute('SELECT * FROM projects WHERE active=1 ORDER BY name').fetchall()
    return render_template('dashboard.html',tickets=rows,stats=stats,projects=projects,selected_status=status)

@app.route('/tickets/new',methods=['POST'])
@roles('user')
def create_ticket():
    project_id=request.form.get('project_id',''); title=request.form.get('title','').strip(); description=plain_text(request.form.get('description','')); priority=request.form.get('priority','Medium')
    project=db().execute('SELECT id FROM projects WHERE id=? AND active=1',(project_id,)).fetchone()
    if not project: flash('Choose an active project.','error'); return redirect(url_for('dashboard'))
    if not title or len(title)>180 or not description or len(description)>10000: flash('Add a title (max 180 characters) and a clear description.','error'); return redirect(url_for('dashboard'))
    if priority not in PRIORITIES: priority='Medium'
    cur=db().execute('INSERT INTO tickets(project_id,title,description,priority,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',(project_id,title,description,priority,'Open',current_user()['id'],now(),now()))
    tid=cur.lastrowid; key=f'FSD-{tid:05d}'; db().execute('UPDATE tickets SET ticket_key=? WHERE id=?',(key,tid)); log_event(tid,'Ticket created.','event')
    try: save_uploads(tid)
    except ValueError as e: db().rollback(); flash(str(e),'error'); return redirect(url_for('dashboard'))
    db().commit(); flash(f'Ticket {key} submitted. The engineering team can pick it up now.','success'); return redirect(url_for('ticket_detail',ticket_id=tid))

@app.route('/tickets/<int:ticket_id>')
@login_required
def ticket_detail(ticket_id):
    u=current_user(); ticket=get_ticket(ticket_id)
    if not ticket: abort(404)
    if not can_view_ticket(ticket,u): abort(403)
    return render_template('ticket_detail.html',ticket=ticket,comments=get_comments(ticket_id),attachments=get_attachments(ticket_id),engineers=db().execute("SELECT id,full_name FROM users WHERE role='engineer' AND active=1 ORDER BY full_name").fetchall())

@app.route('/tickets/<int:ticket_id>/pick',methods=['POST'])
@roles('engineer')
def pick_ticket(ticket_id):
    conn=db(); t=conn.execute('SELECT * FROM tickets WHERE id=?',(ticket_id,)).fetchone()
    if not t: abort(404)
    if t['status'] in ('Closed','Resolved'): flash('Resolved or closed tickets cannot be picked.','error')
    elif t['assigned_to'] not in (None,current_user()['id']): flash('Another engineer has already picked this ticket. Refresh the queue.','error')
    else:
        conn.execute("UPDATE tickets SET assigned_to=?,status='In Progress',updated_at=? WHERE id=? AND (assigned_to IS NULL OR assigned_to=?)",(current_user()['id'],now(),ticket_id,current_user()['id']))
        log_event(ticket_id,f'Ticket picked up by {current_user()["full_name"]}.','event'); conn.commit(); flash('Ticket assigned to you. You’re on it!','success')
    return redirect(url_for('ticket_detail',ticket_id=ticket_id))

@app.route('/tickets/<int:ticket_id>/comment',methods=['POST'])
@login_required
def add_comment(ticket_id):
    u=current_user(); t=get_ticket(ticket_id)
    if not t: abort(404)
    if not can_view_ticket(t,u): abort(403)
    if t['status']=='Closed' and u['role']!='admin': flash('This ticket is closed. Reopen it before adding a reply.','error'); return redirect(url_for('ticket_detail',ticket_id=ticket_id))
    if u['role']=='engineer' and t['assigned_to'] not in (None,u['id']): abort(403)
    body=clean_html(request.form.get('body_html',''))
    if not plain_text(body): flash('Write a reply before posting.','error'); return redirect(url_for('ticket_detail',ticket_id=ticket_id))
    cur=db().execute('INSERT INTO comments(ticket_id,author_id,body_html,created_at,event_type) VALUES(?,?,?,?,?)',(ticket_id,u['id'],body,now(),'comment'))
    try: save_uploads(ticket_id,cur.lastrowid)
    except ValueError as e: db().rollback(); flash(str(e),'error'); return redirect(url_for('ticket_detail',ticket_id=ticket_id))
    db().execute('UPDATE tickets SET updated_at=? WHERE id=?',(now(),ticket_id)); db().commit(); flash('Reply added to the ticket thread.','success'); return redirect(url_for('ticket_detail',ticket_id=ticket_id)+'#conversation')

@app.route('/tickets/<int:ticket_id>/status',methods=['POST'])
@roles('engineer','admin')
def update_status(ticket_id):
    u=current_user(); t=get_ticket(ticket_id)
    if not t: abort(404)
    if u['role']=='engineer' and t['assigned_to']!=u['id']: abort(403)
    status=request.form.get('status','')
    if status not in STATUSES: abort(400)
    if status=='Closed' and t['status'] not in ('Resolved','Closed') and u['role']!='admin': flash('Resolve the ticket before closing it.','error'); return redirect(url_for('ticket_detail',ticket_id=ticket_id))
    resolved=now() if status=='Resolved' else t['resolved_at']; closed=now() if status=='Closed' else (None if status!='Closed' else t['closed_at'])
    db().execute('UPDATE tickets SET status=?,updated_at=?,resolved_at=?,closed_at=? WHERE id=?',(status,now(),resolved,closed,ticket_id)); log_event(ticket_id,f'Status changed to {status}.','event'); db().commit(); flash(f'Ticket moved to {status}.','success'); return redirect(url_for('ticket_detail',ticket_id=ticket_id))

@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    # Attachments are never public. Authorize against the ticket owning this stored path.
    att=db().execute('SELECT ticket_id FROM attachments WHERE stored_name=?',(filename,)).fetchone()
    if not att: abort(404)
    ticket=get_ticket(att['ticket_id'])
    if not ticket or not can_view_ticket(ticket,current_user()): abort(403)
    if current_user()['role']=='engineer' and ticket['assigned_to'] not in (None,current_user()['id']) and ticket['status'] not in ('Resolved','Closed'): abort(403)
    return send_from_directory(UPLOAD_DIR,Path(filename).name,as_attachment=False)

@app.route('/admin')
@roles('admin')
def admin_dashboard():
    conn=db(); projects=conn.execute('SELECT p.*,COUNT(t.id) ticket_count FROM projects p LEFT JOIN tickets t ON t.project_id=p.id GROUP BY p.id ORDER BY p.name').fetchall()
    users=conn.execute('SELECT id,username,full_name,role,active,created_at FROM users ORDER BY role,full_name').fetchall()
    stats={r['status']:r['n'] for r in conn.execute('SELECT status,COUNT(*) n FROM tickets GROUP BY status').fetchall()}
    recent=conn.execute('SELECT t.*,p.name project_name,c.full_name creator_name,a.full_name assignee_name FROM tickets t JOIN projects p ON p.id=t.project_id JOIN users c ON c.id=t.created_by LEFT JOIN users a ON a.id=t.assigned_to ORDER BY t.updated_at DESC LIMIT 8').fetchall()
    return render_template('admin.html',projects=projects,users=users,stats=stats,recent=recent)

@app.route('/admin/projects',methods=['POST'])
@roles('admin')
def add_project():
    name=request.form.get('name','').strip(); description=request.form.get('description','').strip()
    if not name or len(name)>100: flash('Project name is required (max 100 characters).','error')
    else:
        try: db().execute('INSERT INTO projects(name,description,created_at) VALUES(?,?,?)',(name,description[:500],now())); db().commit(); flash(f'Project “{name}” added.','success')
        except sqlite3.IntegrityError: flash('A project with that name already exists.','error')
    return redirect(url_for('admin_dashboard')+'#projects')
@app.route('/admin/projects/<int:project_id>/toggle',methods=['POST'])
@roles('admin')
def toggle_project(project_id):
    p=db().execute('SELECT * FROM projects WHERE id=?',(project_id,)).fetchone()
    if not p: abort(404)
    db().execute('UPDATE projects SET active=? WHERE id=?',(0 if p['active'] else 1,project_id)); db().commit(); flash('Project updated.','success'); return redirect(url_for('admin_dashboard')+'#projects')
@app.route('/admin/users',methods=['POST'])
@roles('admin')
def add_user():
    username=request.form.get('username','').strip().lower(); full=request.form.get('full_name','').strip(); role=request.form.get('role','user'); password=request.form.get('password','')
    if not re.fullmatch(r'[a-z0-9._-]{3,40}',username): flash('Username must be 3–40 characters (letters, numbers, dot, underscore, hyphen).','error')
    elif not full or len(full)>100: flash('Enter the user’s full name.','error')
    elif role not in ('user','engineer','admin'): flash('Choose a valid role.','error')
    elif len(password)<12: flash('Temporary password must be at least 12 characters.','error')
    else:
        try: db().execute('INSERT INTO users(username,full_name,password_hash,role,created_at) VALUES(?,?,?,?,?)',(username,full,generate_password_hash(password),role,now())); db().commit(); flash(f'Account created for {full}. Share the temporary password securely.','success')
        except sqlite3.IntegrityError: flash('That username is already in use.','error')
    return redirect(url_for('admin_dashboard')+'#users')
@app.route('/admin/users/<int:user_id>/toggle',methods=['POST'])
@roles('admin')
def toggle_user(user_id):
    if user_id==current_user()['id']: flash('You cannot deactivate your own account.','error'); return redirect(url_for('admin_dashboard')+'#users')
    person=db().execute('SELECT * FROM users WHERE id=?',(user_id,)).fetchone()
    if not person: abort(404)
    db().execute('UPDATE users SET active=? WHERE id=?',(0 if person['active'] else 1,user_id)); db().commit(); flash('User account updated.','success'); return redirect(url_for('admin_dashboard')+'#users')

@app.route('/health')
def health(): return {'status':'ok','database':'sqlite'},200
@app.errorhandler(403)
def forbidden(_): return render_template('error.html',code=403,message='You don’t have permission to view this page.'),403
@app.errorhandler(404)
def not_found(_): return render_template('error.html',code=404,message='We couldn’t find that page or ticket.'),404
@app.errorhandler(413)
def too_large(_): return render_template('error.html',code=413,message='Upload too large. Keep each screenshot under 5 MB and the request under 10 MB.'),413

if __name__=='__main__': app.run(host='0.0.0.0',port=int(os.getenv('PORT','8000')),debug=False)
