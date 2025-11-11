from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
import random
import os

app = Flask(__name__)
app.secret_key = "mindease_secret_key"

# --- Database Setup ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mind_ease.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), default='client')
    age = db.Column(db.Integer, nullable=True)
    gender = db.Column(db.String(10), nullable=True)
    result = db.Column(db.String(20), nullable=True)  # will store depression/anxiety/stress



# --- Create the database ---
with app.app_context():
    db.create_all()


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

        user = User.query.filter_by(email=email).first()
        if user and user.password == password:
            session['user_email'] = user.email
            session['user_role'] = user.role

            flash(f"✅ Welcome back, {user.role.capitalize()}!", "success")

            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('client_dashboard', email=user.email))
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

        if not email or "@" not in email:
            flash("❌ Please enter a valid email address.", "error")
            return redirect(url_for('register'))
        if not password or len(password) < 6:
            flash("❌ Password must be at least 6 characters long.", "error")
            return redirect(url_for('register'))
        if password != confirm:
            flash("❌ Passwords do not match.", "error")
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("⚠️ Email already registered. Please log in.", "info")
            return redirect(url_for('login'))

        new_user = User(email=email, password=password, role='client')
        db.session.add(new_user)
        db.session.commit()

        flash("✅ Registration successful! You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/client/<email>')
def client_dashboard(email):
    tasks = [
        "Take a deep breath and stretch for 2 minutes 🌿",
        "Write down 3 things you're grateful for today 💖",
        "Go for a short walk or stand up and move around 🚶‍♀️",
        "Drink a glass of water and rest your eyes 💧",
        "Listen to your favorite calm music 🎵",
        "Do 5 minutes of slow breathing 🧘‍♀️",
        "Message a friend and say hello 💌"
    ]
    daily_tasks = random.sample(tasks, 3)
    return render_template('client_dashboard.html', email=email, tasks=daily_tasks)


@app.route('/admin')
def admin_dashboard():
    # Only admin can access
    if session.get('user_role') != 'admin':
        flash("⚠️ Access denied. Admins only!", "error")
        return redirect(url_for('home'))

    users = User.query.all()
    return render_template('admin.html', users=users)


@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    # Only admin can delete users
    if session.get('user_role') != 'admin':
        flash("⚠️ You are not authorized to perform this action.", "error")
        return redirect(url_for('home'))

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash("🗑️ User deleted successfully.", "success")
    else:
        flash("❌ User not found.", "error")
    return redirect(url_for('admin_dashboard'))


@app.route('/depression')
def depression():
    return render_template('depression.html')


@app.route('/anxiety')
def anxiety():
    return render_template('anxiety.html')


@app.route('/stress')
def stress():
    return render_template('stress.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("👋 You’ve been logged out successfully.", "info")
    return redirect(url_for('home'))


@app.route('/assessment', methods=['GET', 'POST'])
def assessment():
    if request.method == 'POST':
        # your existing logic to evaluate results here
        score = sum(int(request.form.get(f'q{i}', 0)) for i in range(1, 11))
        if score >= 25:
            result = "depression"
            tasks = [
                "Write down three things you're grateful for 🌻",
                "Listen to a comforting song 🎧",
                "Reach out to someone you trust 🤝",
                "Spend time outdoors ☀️",
                "Do a 10-minute guided meditation 🧘‍♀️"
            ]
        elif 15 <= score < 25:
            result = "anxiety"
            tasks = [
                "Practice slow breathing for 5 minutes 🌬️",
                "Declutter a small space 🧺",
                "Write your worries and let them go ✍️",
                "Try gentle stretching or yoga 🧘‍♂️",
                "Take a break from your phone 📵"
            ]
        elif 10 <= score < 15:
            result = "stress"
            tasks = [
                "Drink water and take deep breaths 💧",
                "Listen to relaxing sounds 🎶",
                "Take a short walk 🌳",
                "Do something creative 🎨",
                "Have a quiet moment for yourself 🌙"
            ]
        else:
            result = "none"
            tasks = None

        return render_template('assessment_result.html', result=result, tasks=tasks)

    return render_template('assessment.html')


@app.route('/result/<category>')
def result(category):
    task_sets = {
        'depression': [
            "Write down 3 things you're grateful for today 🌸",
            "Spend 10 minutes in sunlight ☀️",
            "Listen to uplifting music 🎵",
            "Message someone you trust 💌",
            "Take a gentle walk outdoors 🚶‍♀️"
        ],
        'anxiety': [
            "Try deep breathing for 5 minutes 🧘‍♀️",
            "Ground yourself using the 5-4-3-2-1 technique 👣",
            "Avoid caffeine for a day ☕",
            "Write down your current worry and a positive response ✍️",
            "Practice a guided meditation 🪷"
        ],
        'stress': [
            "Stretch or move for 3 minutes 🧍‍♀️",
            "Take a 15-minute break from screens 📵",
            "Organize your space 🌼",
            "Drink a full glass of water 💧",
            "Journal 3 small wins today ✨"
        ]
    }
    tasks = task_sets.get(category, [])
    return render_template('result.html', category=category, tasks=tasks)


if __name__ == '__main__':
    app.run(debug=True)
