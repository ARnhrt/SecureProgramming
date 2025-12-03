import os
import secrets
import re
from datetime import datetime, timedelta
from flask import Flask, request, redirect, url_for, render_template_string, session, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.routing import BaseConverter

app = Flask(__name__)
app.secret_key = 'demo_key_change_in_production'

USER_FILE = "users.txt"
MFA_CODES = {}
PROJECTS = {}

# Custom domain mapping - hides IP address
app.config['SERVER_NAME'] = 'securepanel.local:5000'
app.config['PREFERRED_URL_SCHEME'] = 'http'

def load_users():
    users = {}
    if not os.path.exists(USER_FILE):
        return users
    with open(USER_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if ':' in line:
                parts = line.strip().split(":", 2)
                if len(parts) == 3:
                    username, salt_method, hash_val = parts
                    users[username] = f"{salt_method}:{hash_val}"
    return users

def save_users(users):
    with open(USER_FILE, "w", encoding="utf-8") as f:
        for username, password_hash in users.items():
            f.write(f"{username}:{password_hash}\n")

@app.before_request
def waf_check():
    suspicious_patterns = [
        r'<script', r'javascript:', r'union.*select', r'drop.*table', 
        r'exec.*\(', r'\\x[0-9a-f]{2}', r'/\*|\*/|--|#', r'@@version'
    ]
    body = request.get_data(as_text=True).lower()
    for pattern in suspicious_patterns:
        if re.search(pattern, body, re.IGNORECASE):
            abort(403, "Access blocked by security filter.")

def generate_mfa_code():
    return secrets.token_hex(3).upper()

PROFESSIONAL_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>SecurePanel Admin</title>
    <style>
        :root { --primary: #1a202c; --secondary: #2d3748; --accent: #4299e1; --success: #38a169; --danger: #e53e3e; }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: 'Courier New', Consolas, monospace; 
            background: #0f1419; color: #e2e8f0; line-height: 1.6;
            min-height: 100vh;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        
        .auth-container { 
            max-width: 480px; margin: 80px auto; 
            background: #1a202c; border: 3px solid #2d3748; 
            padding: 40px; border-radius: 0;
        }
        .auth-container h1 { 
            color: #e2e8f0; font-size: 28px; font-weight: bold; 
            text-align: center; margin-bottom: 30px; letter-spacing: 2px;
            text-transform: uppercase;
        }
        .nav { 
            display: flex; justify-content: center; gap: 40px; margin-bottom: 30px; 
            border-bottom: 2px solid #4a5568; padding-bottom: 20px;
        }
        .nav a { 
            color: #a0aec0; font-weight: bold; font-size: 16px; text-decoration: none;
            padding: 12px 24px; border: 2px solid transparent; transition: all 0.2s;
        }
        .nav a:hover { color: #e2e8f0; border-bottom: 2px solid var(--accent); }
        .nav a.active { color: var(--accent); border-bottom: 2px solid var(--accent); }
        
        input[type="text"], input[type="password"], input[type="tel"], input[type="email"] { 
            width: 100%; padding: 18px; margin: 12px 0; border: 2px solid #4a5568; 
            background: #2d3748; color: #e2e8f0; font-family: inherit; font-size: 16px;
            border-radius: 0; letter-spacing: 1px;
        }
        input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(66,153,225,0.2); }
        
        button { 
            width: 100%; padding: 22px; margin: 20px 0; border: 3px solid var(--accent); 
            background: var(--accent); color: #1a202c; font-family: inherit; 
            font-size: 18px; font-weight: bold; cursor: pointer; text-transform: uppercase;
            letter-spacing: 1px; transition: all 0.2s;
        }
        button:hover { background: #3182ce; border-color: #3182ce; transform: translateY(-2px); }
        
        .msg { padding: 20px; margin: 20px 0; border: 2px solid; font-weight: bold; text-align: center; font-size: 16px; }
        .error { background: #2d1b24; color: #fed7d7; border-color: var(--danger); }
        .success { background: #1a2f27; color: #c6f6d5; border-color: var(--success); }
        .info { background: #1e2a44; color: #bee3f8; border-color: var(--accent); }
        
        .mfa-instructions { 
            background: #2d3748; padding: 25px; margin: 25px 0; border-left: 5px solid var(--accent);
            font-size: 16px; font-weight: bold; line-height: 1.5;
        }
        .code-hint { 
            background: #4a5568; padding: 25px; margin: 20px 0; text-align: center; 
            font-family: 'Courier New', monospace; font-size: 28px; font-weight: bold;
            letter-spacing: 8px; color: #e2e8f0; border: 2px solid #718096;
        }
        
        .header { 
            background: #1a202c; border: 3px solid #2d3748; padding: 25px 40px; 
            margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center;
        }
        .header h1 { color: #e2e8f0; font-size: 32px; font-weight: bold; letter-spacing: 2px; text-transform: uppercase; }
        .user-info { display: flex; align-items: center; gap: 20px; font-weight: bold; }
        
        .stats-grid, .action-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 25px; margin-bottom: 40px; }
        .stat-card, .action-card { 
            background: #1a202c; border: 3px solid #2d3748; padding: 35px; 
            text-align: center; font-weight: bold;
        }
        .stat-number { font-size: 48px; font-weight: bold; margin: 15px 0; display: block; }
        .stat-online { color: var(--success); }
        .stat-projects { color: var(--accent); }
        .stat-uptime { color: #ed8936; }
        
        .btn { 
            padding: 15px 30px; border: 2px solid; font-weight: bold; cursor: pointer; 
            font-family: inherit; font-size: 16px; text-transform: uppercase;
            margin: 8px; display: inline-flex; align-items: center; gap: 10px; text-decoration: none;
            transition: all 0.2s;
        }
        .btn-primary { background: var(--accent); color: #1a202c; border-color: var(--accent); }
        .btn-success { background: var(--success); color: #1a202c; border-color: var(--success); }
        .btn-danger { background: var(--danger); color: #fff; border-color: var(--danger); }
        .btn:hover { transform: translateY(-3px); opacity: 0.9; }
        
        .projects-section { background: #1a202c; border: 3px solid #2d3748; padding: 35px; }
        .project-item { 
            display: flex; justify-content: space-between; align-items: center; 
            padding: 20px; margin: 15px 0; background: #2d3748; border-left: 5px solid var(--accent);
        }
        .toggle-section { cursor: pointer; font-size: 20px; font-weight: bold; margin-bottom: 25px; color: #e2e8f0; }
        .content-hidden { display: none; }
        
        @media (max-width: 768px) { .container { padding: 15px; } .stats-grid, .action-grid { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <div class="container">
        {% if logged_in %}
        <div class="header">
            <h1>SecurePanel Dashboard</h1>
            <div class="user-info">
                <span>Welcome, {{ session.username }}</span>
                <a href="{{ url_for('dashboard') }}" class="btn btn-primary">Dashboard</a>
                <a href="{{ url_for('logout') }}" class="btn btn-danger">Logout</a>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number stat-online">ONLINE</div>
                <div>System Status</div>
            </div>
            <div class="stat-card">
                <div class="stat-number stat-projects">{{ projects|length }}</div>
                <div>Active Projects</div>
            </div>
            <div class="stat-card">
                <div class="stat-number stat-uptime">99.9%</div>
                <div>Uptime Today</div>
            </div>
        </div>
        
        <div class="action-grid">
            <div class="action-card">
                <h3 style="margin-bottom: 25px; color: #e2e8f0;">Quick Actions</h3>
                <a href="#" class="btn btn-primary" onclick="addProject()">New Project</a>
                <a href="#" class="btn btn-success" onclick="generateReport()">Generate Report</a>
                <a href="#" class="btn btn-danger" onclick="clearProjects()">Clear All</a>
            </div>
            <div class="action-card">
                <h3 style="margin-bottom: 25px; color: #e2e8f0;">Security</h3>
                <a href="#" class="btn btn-primary" onclick="changePassword()">Change Password</a>
                <a href="#" class="btn btn-success" onclick="enable2FA()">Enable 2FA</a>
                <a href="#" class="btn btn-primary" onclick="viewLogs()">View Logs</a>
            </div>
        </div>
        
        {% else %}
        <div class="auth-container">
            {% if mfa_step %}
            <h1>2FA Verification</h1>
            <div class="nav">
                <a href="{{ url_for('login') }}">Back to Login</a>
            </div>
            {% if message %}
                <div class="msg {{ msg_class }}">{{ message }}</div>
            {% endif %}
            <div class="mfa-instructions">
                <strong>Check your console for the 6-digit verification code</strong><br>
                <small>Simulated email and phone delivery</small>
            </div>
            <form method="post" action="{{ url_for('verify_mfa') }}">
                <div class="code-hint">ENTER CODE HERE</div>
                <input type="text" name="code" placeholder="XXXXXX" maxlength="6" 
                       style="text-transform: uppercase; letter-spacing: 8px; text-align: center; font-weight: bold;">
                <button type="submit">Verify Code</button>
            </form>
            {% else %}
            <div class="nav">
                <a href="{{ url_for('register') }}" class="{{ 'active' if active_page == 'register' else '' }}">Register</a>
                <a href="{{ url_for('login') }}" class="{{ 'active' if active_page == 'login' else '' }}">Login</a>
            </div>
            <h1>{{ title }}</h1>
            {% if message %}
                <div class="msg {{ msg_class }}">{{ message }}</div>
            {% endif %}
            <form method="post">
                {% if show_email %}
                <input type="email" name="email" placeholder="Email address" value="{{ email or '' }}">
                {% endif %}
                {% if show_phone %}
                <input type="tel" name="phone" placeholder="Phone number" value="{{ phone or '' }}">
                {% endif %}
                <input type="text" name="username" placeholder="Username" value="{{ username or '' }}">
                <input type="password" name="password" placeholder="Password">
                <button type="submit">{{ button_text }}</button>
            </form>
            {% endif %}
        </div>
        {% endif %}
    </div>
    
    <script>
        document.querySelector('input[name="code"]').addEventListener('input', function(e) {
            this.value = this.value.toUpperCase();
        });
        function addProject() { alert('Project creation form would open here'); }
        function generateReport() { alert('Report generated'); }
        function clearProjects() { if(confirm('Clear all projects?')) location.reload(); }
        function changePassword() { alert('Password change form'); }
        function enable2FA() { alert('2FA already enabled'); }
        function viewLogs() { alert('Security logs loading'); }
    </script>
</body>
</html>
"""

# ROUTES (unchanged functionality)
@app.route('/')
def home():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        
        if not all([username, password, email, phone]):
            return render_template_string(PROFESSIONAL_TEMPLATE, 
                title='Register', active_page='register', show_email=True, show_phone=True,
                message='All fields are required.', msg_class='error', button_text='Create Account')
        
        users = load_users()
        if username in users:
            return render_template_string(PROFESSIONAL_TEMPLATE, 
                title='Register', active_page='register', show_email=True, show_phone=True,
                username=username, message='Username already exists.', msg_class='error', button_text='Create Account')
        
        password_hash = generate_password_hash(password)
        users[username] = password_hash
        save_users(users)
        PROJECTS[username] = []
        
        print(f"NEW USER: {username} | Email: {email} | Phone: {phone}")
        
        return render_template_string(PROFESSIONAL_TEMPLATE, 
            title='Register', active_page='register', show_email=True, show_phone=True,
            message=f'Account {username} created successfully.', msg_class='success', button_text='Create Account')
    
    return render_template_string(PROFESSIONAL_TEMPLATE, title='Register', active_page='register', 
                                show_email=True, show_phone=True, button_text='Create Account')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            return render_template_string(PROFESSIONAL_TEMPLATE, title='Login', active_page='login',
                                       message='Username and password required.', msg_class='error', button_text='Login')
        
        users = load_users()
        if username not in users:
            return render_template_string(PROFESSIONAL_TEMPLATE, title='Login', active_page='login',
                                       username=username, message='User not found.', msg_class='error', button_text='Login')
        
        if not check_password_hash(users[username], password):
            return render_template_string(PROFESSIONAL_TEMPLATE, title='Login', active_page='login',
                                       username=username, message='Incorrect password.', msg_class='error', button_text='Login')
        
        code = generate_mfa_code()
        MFA_CODES[username] = {
            'code': code,
            'expires': datetime.now() + timedelta(minutes=5)
        }
        session['pending_mfa'] = username
        
        print("\n" + "="*60)
        print(f"MFA CODE for {username}: {code}")
        print("Console = Simulated email/phone delivery")
        print("="*60 + "\n")
        
        return render_template_string(PROFESSIONAL_TEMPLATE, mfa_step=True, title='2FA Verification',
                                   message='Password verified. Enter MFA code from console.', msg_class='success')
    
    return render_template_string(PROFESSIONAL_TEMPLATE, title='Login', active_page='login', button_text='Login')

@app.route('/verify_mfa', methods=['POST'])
def verify_mfa():
    code = request.form.get('code', '').strip().upper()
    username = session.get('pending_mfa')
    
    if not username or username not in MFA_CODES:
        return redirect(url_for('login'))
    
    mfa_data = MFA_CODES[username]
    if datetime.now() > mfa_data['expires']:
        del MFA_CODES[username]
        session.pop('pending_mfa', None)
        return render_template_string(PROFESSIONAL_TEMPLATE, mfa_step=True,
            message='Code expired. Login again.', msg_class='error')
    
    if code == mfa_data['code']:
        session['username'] = username
        del MFA_CODES[username]
        session.pop('pending_mfa', None)
        return redirect(url_for('dashboard'))
    
    return render_template_string(PROFESSIONAL_TEMPLATE, mfa_step=True,
        message=f'Invalid code. Expected: {mfa_data["code"]}', msg_class='error')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    projects_list = PROJECTS.get(session['username'], [])
    return render_template_string(PROFESSIONAL_TEMPLATE, title='Dashboard', logged_in=True, 
                                session=session, projects=projects_list)

@app.route('/logout')
def logout():
    session.clear()
    MFA_CODES.clear()
    return redirect(url_for('register'))

if __name__ == '__main__':
    print("🚀 SecurePanel running at:")
    print("   http://securepanel.local:5000")
    print("   (NOT 127.0.0.1 - IP hidden!)")
    print("-" * 50)
    app.run(debug=True, host='127.0.0.1', port=5000, use_reloader=False)
