import os
from flask import Flask, request, redirect, url_for, render_template_string, session

app = Flask(__name__)
app.secret_key = 'demo_key_change_in_production'

USER_FILE = "users.txt"

def load_users():
    users = {}
    if not os.path.exists(USER_FILE):
        return users
    with open(USER_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if ':' in line:
                username, password = line.strip().split(":", 1)
                users[username] = password  # Overwrites if duplicate (flaw!)
    return users

def save_users(users):
    with open(USER_FILE, "w", encoding="utf-8") as f:
        for username, password in users.items():
            f.write(f"{username}:{password}\n")

SIMPLE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>User Portal</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            max-width: 500px; 
            margin: 50px auto; 
            padding: 20px; 
            background: #f5f5f5; 
            color: #333;
        }
        .card { 
            background: white; 
            padding: 30px; 
            border-radius: 10px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 { color: #2c3e50; margin-bottom: 10px; }
        .nav { 
            margin-bottom: 20px; 
            padding-bottom: 10px; 
            border-bottom: 1px solid #eee;
        }
        .nav a { 
            margin-right: 15px; 
            text-decoration: none; 
            color: #3498db; 
            font-weight: bold;
        }
        .nav a.active { color: #e74c3c; }
        input[type="text"], input[type="password"] { 
            width: 100%; 
            padding: 10px; 
            margin: 5px 0 15px 0; 
            border: 1px solid #ddd; 
            border-radius: 5px; 
            box-sizing: border-box;
        }
        button { 
            background: #3498db; 
            color: white; 
            padding: 10px 20px; 
            border: none; 
            border-radius: 5px; 
            cursor: pointer; 
            width: 100%;
        }
        button:hover { background: #2980b9; }
        .msg { 
            padding: 10px; 
            margin: 10px 0; 
            border-radius: 5px; 
        }
        .error { background: #ffeaa7; color: #d63031; border: 1px solid #fdcb6e; }
        .success { background: #00b894; color: white; }
        .wip { text-align: center; color: #7f8c8d; }
        .logout { background: #e74c3c !important; }
        .logout:hover { background: #c0392b !important; }
    </style>
</head>
<body>
    <div class="card">
        {% if logged_in %}
        <h1>Welcome, {{ session.username }}!</h1>
        <div class="nav">
            <a href="{{ url_for('dashboard') }}" class="active">Dashboard</a>
            <a href="{{ url_for('logout') }}" class="logout">Logout</a>
        </div>
        <div class="wip">
            <h2>Work in Progress</h2>
            <p>Your secure area is under development.</p>
            <ul>
                <li>Project Management</li>
                <li>User Settings</li>
                <li>Reports</li>
            </ul>
        </div>
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
            <input type="text" name="username" placeholder="Username" value="{{ username or '' }}">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">{{ button_text }}</button>
        </form>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            return render_template_string(SIMPLE_TEMPLATE, title='Register', active_page='register',
                                       message='Please fill in all fields.', msg_class='error')
        
        # FLAW 1: Always allows registration (no duplicate check)
        users = load_users()
        if username in users:  
            return render_template_string(
                SIMPLE_TEMPLATE, title='Register', active_page='register',
                message='Username already exists. Please choose another.', msg_class='error',
                username=username, button_text='Register'
            )
        users[username] = password  # Overwrites existing user!
        save_users(users)
        
        return render_template_string(SIMPLE_TEMPLATE, title='Register', active_page='register',
                                   message=f'Account created for {username}!', msg_class='success')
    
    return render_template_string(SIMPLE_TEMPLATE, title='Register', active_page='register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', ' ').strip() ## Username is checked with password
        users = load_users()
        
        # FLAW 2: Only checks if username exists, ignores password
        if username in users and users[username] == password: ## Username is checked with password
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template_string(SIMPLE_TEMPLATE, title='Login', active_page='login',
                                       message='Login failed. Try again.', msg_class='error', username=username)
    
    return render_template_string(SIMPLE_TEMPLATE, title='Login', active_page='login')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template_string(SIMPLE_TEMPLATE, title='Dashboard', logged_in=True, session=session)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('register'))

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1')
