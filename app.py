from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
import random
import os
from datetime import datetime, timedelta, date
from flask_migrate import Migrate

app = Flask(__name__)
app.secret_key = "mindease_secret_key"

# --- Database Setup ---
# NOTE: Using a relative path for the DB, it may be created in an 'instance' folder
# depending on your Flask configuration, which is fine.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mind_ease.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# --- MASTER TASK POOL ---
MASTER_TASKS = {
    "depression": {
        "Mind": [
            "Write down 3 things you're grateful for today 🌸",
            "Challenge one negative thought 🧠",
            "Listen to uplifting music for 15 minutes 🎵"
        ],
        "Body": [
            "Take a gentle walk outdoors for 10 minutes 🚶‍♀️",
            "Do a full-body stretch 🧘‍♂️",
            "Prepare a nutritious meal or snack 🍎"
        ],
        "Spirit": [
            "Message someone you trust and have a brief chat 💌",
            "Spend 10 minutes in sunlight ☀️",
            "Do a 10-minute guided meditation 🧘‍♀️"
        ]
    },
    "anxiety": {
        "Mind": [
            "Practice slow, box breathing for 5 minutes 🌬️",
            "Identify what you *can* control and what you *cannot* 📝",
            "Read a book for 20 minutes (not news/social media) 📚"
        ],
        "Body": [
            "Ground yourself using the 5-4-3-2-1 technique 👣",
            "Tense and relax each muscle group 🧍",
            "Avoid caffeine or alcohol today ☕"
        ],
        "Spirit": [
            "Declutter a small space (e.g., a drawer or desktop) 🧺",
            "Try a short art or doodle session 🎨",
            "Write your worries in a 'worry box' and close it ✍️"
        ]
    },
    "stress": {
        "Mind": [
            "Journal 3 small wins you had today ✨",
            "Plan your top 3 priorities for tomorrow 📅",
            "Listen to calming nature sounds 🎶"
        ],
        "Body": [
            "Stretch or move for 5 minutes 🧍‍♀️",
            "Drink a full glass of water and notice the sensation 💧",
            "Take a 15-minute break from screens 📵"
        ],
        "Spirit": [
            "Engage in a quick, fun hobby 🕹️",
            "Have a quiet moment just for yourself 🌙",
            "Light a favorite candle or use aromatherapy 🕯️"
        ]
    },
    "none": {
        "Mind": ["Write down a positive affirmation for the day 💖"],
        "Body": ["Take a deep breath and stretch for 2 minutes 🌿"],
        "Spirit": ["Say 'Hello' to a stranger or check in on a friend 👋"]
    }
}


# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), default='client')
    age = db.Column(db.Integer, nullable=True)
    gender = db.Column(db.String(10), nullable=True)
    last_result = db.Column(db.String(50), nullable=True)
    tasks = db.Column(db.PickleType, nullable=True)
    tasks_generated_on = db.Column(db.Date, nullable=True)
    weekly_insights = db.Column(db.PickleType, nullable=True)

    # CORRECTED PATH to match your 'static/images' folder structure
    avatar = db.Column(db.String(200), nullable=True, default='/static/images/neutral.png')

    def assign_default_avatar(self):
        # Assigns avatar based on gender using the corrected path
        if self.gender and self.gender.lower().startswith('m'):
            self.avatar = url_for_static('images/male.png')
        elif self.gender and self.gender.lower().startswith('f'):
            self.avatar = url_for_static('images/female.png')
        else:
            self.avatar = url_for_static('images/neutral.png')


def url_for_static(path: str):
    return f"/static/{path}"


# --- HELPER FUNCTIONS ---

def generate_daily_tasks(user_result: str):
    """
    Generates a new set of tasks (Mind, Body, Spirit) based on the user's last assessment result.
    The tasks now include the 'category'.
    """
    result_key = user_result if user_result in MASTER_TASKS else "none"
    task_pool = MASTER_TASKS[result_key]

    new_tasks = []

    for category in ["Mind", "Body", "Spirit"]:
        if category in task_pool and task_pool[category]:
            selected_task_text = random.choice(task_pool[category])
            # ADDED 'category' KEY
            new_tasks.append({
                "text": selected_task_text,
                "done": False,
                "category": category  # Include the category here
            })

    return new_tasks


def check_and_reset_tasks(user: User):
    """
    Checks if a new day has passed and resets tasks if needed.
    """
    today = datetime.utcnow().date()
    reset_needed = False

    if not user.tasks:
        reset_needed = True

    if user.tasks_generated_on and user.tasks_generated_on < today:
        reset_needed = True

    if reset_needed:
        # Update Weekly Insights (Accumulation)
        current_insights = user.weekly_insights or {'week_start': today.isoformat(), 'completed': 0, 'total': 0}

        done_today = sum(1 for t in (user.tasks or []) if t.get('done'))
        total_today = len(user.tasks or [])

        current_insights['completed'] += done_today
        current_insights['total'] += total_today

        # Reset task list and generation date
        user.tasks = generate_daily_tasks(user.last_result)
        user.tasks_generated_on = today
        user.weekly_insights = current_insights
        return True

    return False


def compute_progress(tasks):
    if not tasks:
        return 0
    total = len(tasks)
    done = sum(1 for t in tasks if t.get('done'))
    return int((done / total) * 100)


# --- ROUTES ---
@app.route('/')
def home():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

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

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("⚠️ Email already registered. Please log in.", "info")
            return redirect(url_for('login'))

        new_user = User(email=email, password=password, role='client')

        if age:
            try:
                new_user.age = int(age)
            except ValueError:
                new_user.age = None
        if gender:
            new_user.gender = gender

        # Assign default avatar based on gender (using corrected path)
        new_user.assign_default_avatar()

        # Initialize
        new_user.tasks = []
        new_user.tasks_generated_on = None
        new_user.weekly_insights = {'week_start': datetime.utcnow().isoformat(), 'completed': 0, 'total': 0}

        db.session.add(new_user)
        db.session.commit()

        flash("✅ Registration successful! You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/client/<email>')
def client_dashboard(email):
    # Security check: Ensure the logged-in user matches the dashboard user, or is an admin
    if session.get('user_email') != email and session.get('user_role') != 'admin':
        flash("⚠️ Access denied.", "error")
        return redirect(url_for('home'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('home'))

    # CHECK AND RESET LOGIC
    reset_performed = check_and_reset_tasks(user)

    if reset_performed:
        db.session.commit()
        if len(user.tasks) > 0:
            flash("☀️ Your new daily self-care tasks have been loaded!", "info")

    progress = compute_progress(user.tasks)

    return render_template(
        'client_dashboard.html',
        user=user,
        tasks=user.tasks,
        progress=progress
    )


@app.route('/toggle_task', methods=['POST'])
def toggle_task():
    # Toggle a task done/undone via AJAX.
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

    user.tasks[idx]['done'] = not bool(user.tasks[idx].get('done'))
    db.session.commit()

    return jsonify({"success": True, "done": user.tasks[idx]['done'], "progress": compute_progress(user.tasks)})


# --- Remaining Routes (Unchanged) ---

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
        elif 15 <= score < 25:
            result = "anxiety"
        elif 10 <= score < 15:
            result = "stress"
        else:
            result = "none"

        tasks = generate_daily_tasks(result)

        if session.get('user_email'):
            user = User.query.filter_by(email=session['user_email']).first()
            if user:
                user.last_result = result
                user.tasks = tasks
                user.tasks_generated_on = datetime.utcnow().date()
                user.weekly_insights = {'week_start': datetime.utcnow().isoformat(), 'completed': 0,
                                        'total': len(tasks)}
                db.session.commit()

        return render_template('assessment_result.html', result=result, tasks=tasks)

    return render_template('assessment.html')


@app.route('/result/<category>')
def result(category):
    tasks = generate_daily_tasks(category)

    return render_template('result.html', category=category, tasks=tasks)


@app.route("/about")
def about():
    return render_template("about.html")


if __name__ == '__main__':
    app.run(debug=True)