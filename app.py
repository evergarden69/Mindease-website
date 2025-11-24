# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
import random
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "mindease_secret_key"

# --- Database Setup ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mind_ease.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
from flask_migrate import Migrate
migrate = Migrate(app, db)


# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), default='client')
    age = db.Column(db.Integer, nullable=True)
    gender = db.Column(db.String(10), nullable=True)
    last_result = db.Column(db.String(50), nullable=True)
    # store tasks as a Python object (list of dicts): [{'text': '...', 'done': False}, ...]
    tasks = db.Column(db.PickleType, nullable=True)
    # store weekly insights (simple dict)
    weekly_insights = db.Column(db.PickleType, nullable=True)
    avatar = db.Column(db.String(200), nullable=True)  # path to default avatar
    avatar = db.Column(db.String(200), nullable=False, default='default_avatar.png')

    def assign_default_avatar(self):
        # choose default based on gender
        if self.gender and self.gender.lower().startswith('m'):
            self.avatar = url_for_static('images/avatars/male.png')
        elif self.gender and self.gender.lower().startswith('f'):
            self.avatar = url_for_static('images/avatars/female.png')
        else:
            self.avatar = url_for_static('images/avatars/neutral.png')


def url_for_static(path: str):
    # helper to create a relative path string for DB; will be used in templates via /static/...
    return f"/static/{path}"


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
        age = request.form.get('age')
        gender = request.form.get('gender')

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
        # optional extras
        if age:
            try:
                new_user.age = int(age)
            except ValueError:
                new_user.age = None
        if gender:
            new_user.gender = gender

        # assign default avatar immediately (Option A)
        new_user.avatar = url_for_static('images/avatars/neutral.png')
        if new_user.gender:
            if new_user.gender.lower().startswith('m'):
                new_user.avatar = url_for_static('images/avatars/male.png')
            elif new_user.gender.lower().startswith('f'):
                new_user.avatar = url_for_static('images/avatars/female.png')

        # empty tasks to start
        new_user.tasks = []
        # empty weekly insights
        new_user.weekly_insights = {'week_start': datetime.utcnow().isoformat(), 'completed': 0, 'total': 0}
        db.session.add(new_user)
        db.session.commit()

        flash("✅ Registration successful! You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


def compute_progress(tasks):
    if not tasks:
        return 0
    total = len(tasks)
    done = sum(1 for t in tasks if t.get('done'))
    return int((done / total) * 100)


@app.route('/client/<email>')
def client_dashboard(email):
    user = User.query.filter_by(email=email).first()
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('home'))

    # ensure tasks exist
    if not user.tasks:
        # provide default initial tasks (these will be individual for each result later)
        default_tasks = [
            {"text": "Take a deep breath and stretch for 2 minutes 🌿", "done": False},
            {"text": "Write down 3 things you're grateful for today 💖", "done": False},
            {"text": "Go for a short walk or move around 🚶‍♀️", "done": False}
        ]
        user.tasks = default_tasks
        db.session.commit()

    progress = compute_progress(user.tasks)

    return render_template(
        'client_dashboard.html',
        user=user,
        tasks=user.tasks,
        progress=progress
    )


@app.route('/toggle_task', methods=['POST'])
def toggle_task():
    # Toggle a task done/undone via AJAX. payload: { index: int }
    if 'user_email' not in session:
        return jsonify({"error": "not_logged_in"}), 401

    index = request.json.get('index')
    email = session['user_email']
    user = User.query.filter_by(email=email).first()
    if not user or not isinstance(user.tasks, list):
        return jsonify({"error": "invalid_user"}), 400

    try:
        idx = int(index)
        if idx < 0 or idx >= len(user.tasks):
            raise IndexError
    except Exception:
        return jsonify({"error": "invalid_index"}), 400

    # toggle
    user.tasks[idx]['done'] = not bool(user.tasks[idx].get('done'))
    db.session.commit()

    # update weekly_insights simple counters
    completed = sum(1 for t in user.tasks if t.get('done'))
    total = len(user.tasks)
    user.weekly_insights = user.weekly_insights or {}
    user.weekly_insights['completed'] = completed
    user.weekly_insights['total'] = total
    user.weekly_insights['last_updated'] = datetime.utcnow().isoformat()
    db.session.commit()

    return jsonify({"success": True, "done": user.tasks[idx]['done'], "progress": compute_progress(user.tasks)})


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
        score = sum(int(request.form.get(f'q{i}', 0)) for i in range(1, 11))
        if score >= 25:
            result = "depression"
            tasks = [
                {"text": "Write down three things you're grateful for 🌻", "done": False},
                {"text": "Listen to a comforting song 🎧", "done": False},
                {"text": "Reach out to someone you trust 🤝", "done": False},
                {"text": "Spend time outdoors ☀️", "done": False},
                {"text": "Do a 10-minute guided meditation 🧘‍♀️", "done": False}
            ]
        elif 15 <= score < 25:
            result = "anxiety"
            tasks = [
                {"text": "Practice slow breathing for 5 minutes 🌬️", "done": False},
                {"text": "Declutter a small space 🧺", "done": False},
                {"text": "Write your worries and let them go ✍️", "done": False},
                {"text": "Try gentle stretching or yoga 🧘‍♂️", "done": False},
                {"text": "Take a break from your phone 📵", "done": False}
            ]
        elif 10 <= score < 15:
            result = "stress"
            tasks = [
                {"text": "Drink water and take deep breaths 💧", "done": False},
                {"text": "Listen to relaxing sounds 🎶", "done": False},
                {"text": "Take a short walk 🌳", "done": False},
                {"text": "Do something creative 🎨", "done": False},
                {"text": "Have a quiet moment for yourself 🌙", "done": False}
            ]
        else:
            result = "none"
            tasks = []

        # store results into user if logged in
        if session.get('user_email'):
            user = User.query.filter_by(email=session['user_email']).first()
            if user:
                user.last_result = result
                user.tasks = tasks
                user.weekly_insights = {'week_start': datetime.utcnow().isoformat(), 'completed': 0, 'total': len(tasks)}
                db.session.commit()

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

@app.route("/about")
def about():
    return render_template("about.html")


if __name__ == '__main__':
    # ensure debug off in production
    app.run(debug=True)
