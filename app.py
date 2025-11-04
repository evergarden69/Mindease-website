from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = "mindease_secret_key"

# --- In-memory database (for testing only) ---
USERS = {
    "admin@mindease.com": {"password": "admin123", "role": "admin"},
    "client@mindease.com": {"password": "client123", "role": "client"},
}


# --- ROUTES ---
@app.route('/')
def home():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or "@" not in email:
            flash("❌ Please enter a valid email address.", "error")
            return redirect(url_for('login'))
        if not password:
            flash("❌ Please enter your password.", "error")
            return redirect(url_for('login'))

        user = USERS.get(email)
        if user and user['password'] == password:
            flash(f"✅ Welcome back, {user['role'].capitalize()}!", "success")
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('home'))
        else:
            flash("❌ Invalid email or password. Please try again.", "error")
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm = request.form.get('confirm')

        # --- Basic validation ---
        if not email or "@" not in email:
            flash("❌ Please enter a valid email address.", "error")
            return redirect(url_for('register'))
        if not password or len(password) < 6:
            flash("❌ Password must be at least 6 characters long.", "error")
            return redirect(url_for('register'))
        if password != confirm:
            flash("❌ Passwords do not match.", "error")
            return redirect(url_for('register'))
        if email in USERS:
            flash("⚠️ Email already registered. Please log in.", "info")
            return redirect(url_for('login'))

        # --- Register new user ---
        USERS[email] = {"password": password, "role": "client"}
        flash("✅ Registration successful! You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/admin')
def admin_dashboard():
    return render_template('admin.html')


@app.route('/depression')
def depression():
    return render_template('depression.html')


@app.route('/anxiety')
def anxiety():
    return render_template('anxiety.html')


@app.route('/stress')
def stress():
    return render_template('stress.html')


if __name__ == '__main__':
    app.run(debug=True)

