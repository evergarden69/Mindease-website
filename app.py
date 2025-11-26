from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
import random
import os
from datetime import datetime, timedelta, date
from flask_migrate import Migrate
import pickle

# --- UPDATED IMPORTS ---
# ProfileSettingsForm must be imported here now
from forms import RegisterForm, AccountForm, DiscussionForm, ReplyForm, ProfileSettingsForm, PasswordChangeForm
from werkzeug.security import generate_password_hash, check_password_hash  # CHECK_PASSWORD_HASH IS NOW USED
# Ensure Pickle is accessible for the 'tasks' field (kept the custom type for safety, but tasks fields are removed)
from sqlalchemy.types import TypeDecorator, LargeBinary


# --- Custom Pickle Type (Kept for compatibility, though task fields are removed) ---
class PickledDict(TypeDecorator):
    impl = LargeBinary

    def process_bind_param(self, value, dialect):
        if value is not None:
            return pickle.dumps(value)
        return None

    def process_result_value(self, value, dialect):
        if value is not None:
            return pickle.loads(value)
        return None


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_super_secret_key_that_must_be_changed'

# --- Database Setup ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mind_ease.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)


# --- MASTER TASK POOL REMOVED ---
# (The dictionary MASTER_TASKS has been removed)


# --- Database Models (Cleaned) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=True)
    password = db.Column(db.String(256), nullable=True)
    role = db.Column(db.String(10), default='client')

    buddy_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    # Intake/Demographic Fields
    age = db.Column(db.Integer, nullable=True)
    gender = db.Column(db.String(10), nullable=True)
    location = db.Column(db.String(5), nullable=True)
    dob = db.Column(db.String(10), nullable=True)
    service_therapy = db.Column(db.Boolean, default=False)
    service_psychiatry = db.Column(db.Boolean, default=False)
    service_substance = db.Column(db.Boolean, default=False)
    service_not_sure = db.Column(db.Boolean, default=False)

    # --- TASK FIELDS REMOVED ---
    # last_result = db.Column(db.String(50), nullable=True)
    # tasks = db.Column(PickledDict, nullable=True)
    # tasks_generated_on = db.Column(db.Date, nullable=True)
    # weekly_insights = db.Column(PickledDict, nullable=True)
    # ---------------------------

    avatar = db.Column(db.String(200), nullable=True, default='/static/images/neutral.png')

    def assign_default_avatar(self):
        if self.gender and self.gender.lower().startswith('m'):
            self.avatar = url_for_static('images/male.png')
        elif self.gender and self.gender.lower().startswith('f'):
            self.avatar = url_for_static('images/female.png')
        else:
            self.avatar = url_for_static('images/neutral.png')


# --- Community Models (Unchanged) ---
class Discussion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref=db.backref('discussions', lazy=True))

    category = db.Column(db.String(50), default='General')
    replies_count = db.Column(db.Integer, default=0)


class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    discussion_id = db.Column(db.Integer, db.ForeignKey('discussion.id'), nullable=False)
    discussion = db.relationship('Discussion', backref=db.backref('replies', lazy=True))

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref=db.backref('replies_made', lazy=True))


def url_for_static(path: str):
    return f"/static/{path}"


# --- HELPER FUNCTIONS REMOVED ---
# (generate_daily_tasks, check_and_reset_tasks, compute_progress have been removed)


# ----------------------------------------------------------------------
# --- ROUTES ---
# ----------------------------------------------------------------------

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    from werkzeug.security import check_password_hash

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_email'] = user.email
            session['user_role'] = user.role

            flash(f"Welcome back, {user.role.capitalize()}!", "success")

            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('community_dashboard'))
        else:
            flash("Invalid email or password. Please try again.", "error")
            return redirect(url_for('login'))

    return render_template('login.html')


# --- Registration Routes (Modified to clean up task references) ---
@app.route('/register', methods=['GET', 'POST'])
def register_info():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        if User.query.filter_by(email=email).first():
            flash("Email already registered. Please log in.", "info")
            return redirect(url_for('login'))

        session['reg_data'] = {
            'email': email,
            'location': form.location.data,
            'dob': form.dob.data,
            'service_therapy': form.therapy_services.data,
            'service_psychiatry': form.psychiatry_management.data,
            'service_substance': form.substance_counseling.data,
            'service_not_sure': form.not_sure.data
        }
        flash("Info saved. Please create your account.", "info")
        return redirect(url_for('register_account'))

    return render_template('register.html', form=form)


@app.route('/create-account', methods=['GET', 'POST'])
def register_account():
    form = AccountForm()
    if 'reg_data' not in session:
        flash('Please fill out patient info first.', 'warning')
        return redirect(url_for('register_info'))

    if form.validate_on_submit():

        # Check if username already exists
        if User.query.filter_by(username=form.username.data).first():
            flash("That username is already taken. Please choose another.", "warning")
            return render_template('register_account.html', form=form)

        info = session.pop('reg_data')
        hashed_pw = generate_password_hash(form.password.data)

        new_user = User(
            email=info['email'],
            password=hashed_pw,
            role='client',
            username=form.username.data,
            location=info['location'],
            dob=info['dob'],
            service_therapy=info['service_therapy'],
            service_psychiatry=info['service_psychiatry'],
            service_substance=info['service_substance'],
            service_not_sure=info['service_not_sure'],
            age=form.age.data,
            gender=form.gender.data,
            # Removed initial task setup parameters here
        )
        new_user.assign_default_avatar()

        db.session.add(new_user)
        db.session.commit()

        flash("Account created! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register_account.html', form=form)


# ----------------------------------------------------------------------
# --- COMMUNITY & SETTINGS ROUTES ---
# ----------------------------------------------------------------------

@app.route('/community')
def community_dashboard():
    if 'user_email' not in session:
        flash("Please log in to view the community.", "error")
        return redirect(url_for('login'))

    user = User.query.filter_by(email=session['user_email']).first()
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('home'))

    latest_discussions = Discussion.query.order_by(Discussion.created_at.desc()).limit(10).all()

    return render_template(
        'client_dashboard.html',
        user=user,
        discussions=latest_discussions,
        hide_nav=True
    )


@app.route('/start_discussion', methods=['GET', 'POST'])
def create_discussion():
    if 'user_email' not in session:
        flash("You must be logged in to start a discussion.", "error")
        return redirect(url_for('login'))

    user = User.query.filter_by(email=session['user_email']).first()
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('home'))

    form = DiscussionForm()

    if form.validate_on_submit():
        new_discussion = Discussion(
            title=form.title.data,
            content=form.content.data,
            category=form.category.data,
            user_id=user.id,
            replies_count=0
        )

        db.session.add(new_discussion)
        db.session.commit()

        flash("Your discussion has been posted successfully!", "success")
        return redirect(url_for('community_dashboard'))

    return render_template('create_discussion.html', form=form, user=user, hide_nav=True)


@app.route('/discussion/<int:discussion_id>', methods=['GET', 'POST'])
def view_discussion(discussion_id):
    if 'user_email' not in session:
        flash("You must be logged in to view discussions.", "error")
        return redirect(url_for('login'))

    current_user = User.query.filter_by(email=session['user_email']).first()
    discussion = Discussion.query.get_or_404(discussion_id)

    form = ReplyForm()

    if form.validate_on_submit():
        if not current_user:
            flash("Error: User session invalid.", "error")
            return redirect(url_for('home'))

        new_reply = Reply(
            content=form.content.data,
            discussion_id=discussion.id,
            user_id=current_user.id
        )

        db.session.add(new_reply)

        discussion.replies_count += 1

        db.session.commit()

        flash("Your reply has been posted successfully!", "success")
        return redirect(url_for('view_discussion', discussion_id=discussion.id))

    replies = Reply.query.filter_by(discussion_id=discussion.id).order_by(Reply.created_at.asc()).all()

    return render_template('view_discussion.html',
                           discussion=discussion,
                           replies=replies,
                           form=form,
                           user=current_user,
                           hide_nav=True)


# --- UPDATED PROFILE SETTINGS ROUTE ---
@app.route('/settings', methods=['GET', 'POST'])
def profile_settings():
    if 'user_email' not in session:
        flash("You must be logged in to view settings.", "error")
        return redirect(url_for('login'))

    user = User.query.filter_by(email=session['user_email']).first()
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('home'))

    # 1. Profile Update Form (for username/avatar)
    profile_form = ProfileSettingsForm(obj=user)

    # 2. Password Change Form
    password_form = PasswordChangeForm()

    # --- Profile Form Submission Logic (Checks for the specific submit button data) ---
    if profile_form.validate_on_submit() and profile_form.submit.data:
        if profile_form.username.data != user.username:
            if User.query.filter_by(username=profile_form.username.data).first():
                flash("That username is already taken. Please choose another.", "warning")
                # Need to pass both forms back to the template
                return render_template('settings.html', profile_form=profile_form, password_form=password_form,
                                       user=user)

        user.username = profile_form.username.data
        user.avatar = profile_form.avatar.data

        db.session.commit()
        flash("Profile updated successfully! ✨", "success")
        return redirect(url_for('profile_settings'))

    # --- Password Form Submission Logic (Checks for the specific submit button data) ---
    if password_form.validate_on_submit() and password_form.submit_password.data:
        # 1. Check if the current password is correct
        if not check_password_hash(user.password, password_form.current_password.data):
            flash("Current password entered is incorrect.", "error")
            # Pass both forms back to the template
            return render_template('settings.html', profile_form=profile_form, password_form=password_form, user=user)

        # 2. Hash and update the new password
        user.password = generate_password_hash(password_form.new_password.data)
        db.session.commit()
        flash("Password changed successfully! Please log in again.", "success")
        return redirect(url_for('logout'))

    # --- Initial GET Request (Pass both forms) ---
    return render_template('settings.html', profile_form=profile_form, password_form=password_form, user=user,
                           hide_nav=True)


# --- END OF UPDATED PROFILE SETTINGS ROUTE ---


# ----------------------------------------------------------------------
# --- ADMIN & STATIC ROUTES (ASSESSMENT REMOVED) ---
# ----------------------------------------------------------------------

@app.route('/seed_db')
def seed_db():
    # This route is only for testing/development. DO NOT USE IN PRODUCTION.

    # Ensure a test user exists
    test_user = User.query.filter_by(email='test@client.com').first()
    if not test_user:
        test_user = User(
            email='test@client.com',
            password=generate_password_hash('password'),
            role='client',
            username='TestUser',
            age=30,
            gender='M',
            location='TX',
            dob='01/01/1990',
            # Removed last_result field assignment
        )
        test_user.assign_default_avatar()
        db.session.add(test_user)
        db.session.commit()

    user_id = test_user.id

    if not Discussion.query.first():
        # Create sample discussions
        d1 = Discussion(
            title="What should I do if I think I've been misdiagnosed?",
            content="I was diagnosed with schizophrenia but I'm learning about BPD and I feel it's the cause of my hallucinations. I personally believe I have 5 or potentially more of the 9 symptoms I didn't really understand all of the criteria.",
            user_id=user_id,
            category='Mental health conditions',
            replies_count=1
        )
        d2 = Discussion(
            title="Endless cycle",
            content="Hi, it's hard to move on when your mind never lets go of dates and times that had traumatic events involved. I have worked hard to recover only to have those efforts undermined by my own subconscious. I suffer from cPTSD and psychosis and have recently been looking into EMDR therapy.",
            user_id=user_id,
            category='Caring for myself and others',
            replies_count=0
        )
        d3 = Discussion(
            title="Introduce yourself!",
            content="Welcome to the MindEase Community! Drop a line and tell us about your journey. What brings you here and what are you hoping to find?",
            user_id=user_id,
            category='Introduce yourself',
            replies_count=2
        )
        db.session.add_all([d1, d2, d3])
        db.session.commit()

        # Add replies and update reply counts (d3 needs 2 replies for testing)
        r1 = Reply(
            content="I highly recommend getting a second opinion from a specialist if you feel that strongly. It’s important to have clarity for treatment.",
            discussion_id=d1.id,
            user_id=user_id
        )
        r2 = Reply(
            content="Hello! I'm here for support with anxiety. Glad to be here.",
            discussion_id=d3.id,
            user_id=user_id
        )
        r3 = Reply(
            content="Welcome! You're not alone in this journey.",
            discussion_id=d3.id,
            user_id=user_id
        )

        d3.replies_count = 2

        db.session.add_all([r1, r2, r3])
        db.session.commit()

        flash("Database seeded with test user and 3 discussions!", "success")
    else:
        flash("Database already contains discussions.", "info")

    return redirect(url_for('community_dashboard'))


@app.route('/admin')
def admin_dashboard():
    if session.get('user_role') != 'admin':
        flash("Access denied. Admins only!", "error")
        return redirect(url_for('home'))

    users = User.query.all()
    return render_template('admin.html', users=users)


@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if session.get('user_role') != 'admin':
        flash("You are not authorized to perform this action.", "error")
        return redirect(url_for('home'))

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash("User deleted successfully.", "success")
    else:
        flash(" User not found.", "error")
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


# --- ASSESSMENT ROUTES REMOVED ---
# (@app.route('/assessment') and @app.route('/result/<category>') have been removed)


@app.route("/about")
def about():
    return render_template("about.html")


if __name__ == '__main__':
    with app.app_context():
        # This will ensure the database and tables exist when the app starts.
        db.create_all()
    app.run(debug=True)