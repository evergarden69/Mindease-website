from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
import random
import os
from flask_login import login_required, current_user, LoginManager, UserMixin, login_user, logout_user
from functools import wraps
from datetime import datetime, timedelta, date
from flask_migrate import Migrate
import pickle

from forms import RegisterForm, AccountForm, DiscussionForm, ReplyForm, ProfileSettingsForm, PasswordChangeForm, \
    AddTherapistForm
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.types import TypeDecorator, LargeBinary


def role_required(role):
    """
    Decorator to restrict access to a route based on user role.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                # Log unauthorized access attempt (optional)
                current_app.logger.warning(f"Unauthorized access attempt by {current_user.email} (Role: {current_user.role})")
                abort(403) # Return HTTP 403 Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator




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

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mind_ease.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Function name for the login page route
login_manager.login_message_category = 'info'


class User(UserMixin, db.Model):
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

    avatar = db.Column(db.String(200), nullable=True, default='/static/avatars/neutral_icon.png')


class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    client_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    therapist_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # MUST BE USER ID

    date = db.Column(db.String(20))
    time = db.Column(db.String(20))
    note = db.Column(db.Text)
    service_type = db.Column(db.String(50))  # Added this field to make notification message complete

    status = db.Column(db.String(20), default='Pending',
                       nullable=False)  # 'Pending', 'Accepted', 'Rejected', 'Cancelled'

    client = db.relationship('User', foreign_keys=[client_id],
                             backref=db.backref('client_appointments', lazy='dynamic'))
    therapist = db.relationship('User', foreign_keys=[therapist_id],
                                backref=db.backref('therapist_appointments', lazy='dynamic'))


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


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # Links to the client who needs to see the notification
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    message = db.Column(db.String(300), nullable=False)
    category = db.Column(db.String(20), default='info')  # e.g., 'success', 'danger', 'warning'
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Optional: Back reference to the client user (for easier deletion/lookup)
    client = db.relationship('User', backref=db.backref('notifications', lazy=True))

    def __repr__(self):
        return f'<Notification {self.id}: {self.message[:20]}...>'


@login_manager.user_loader
def load_user(user_id):
    # This must return the User object for the given user_id or None
    return db.session.get(User, int(user_id))


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            # FIX: flask-login requires login_user to actually log the user in
            login_user(user)

            flash(f"Welcome back, {user.role.capitalize()}!", "success")

            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'therapist':  # Redirect therapist to their dashboard
                return redirect(url_for('therapist_dashboard'))
            else:
                # Redirect to the intended page after login, which is the community dashboard
                return redirect(url_for('community_dashboard'))
        else:
            flash("Invalid email or password. Please try again.", "error")
            return redirect(url_for('login'))

    return render_template('login.html')


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
        )

        # Avatar Mapping
        if new_user.gender and new_user.gender.lower().startswith('m'):
            new_user.avatar = url_for('static', filename='avatars/male_icon.png')
        elif new_user.gender and new_user.gender.lower().startswith('f'):
            new_user.avatar = url_for('static', filename='avatars/female_icon.png')
        else:
            new_user.avatar = url_for('static', filename='avatars/neutral_icon.png')

        db.session.add(new_user)
        db.session.commit()

        flash("Account created! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register_account.html', form=form)


@app.route('/community')
@login_required
def community_dashboard():
    user = current_user

    # Check and update the avatar URL from the database if the current URL is just the filename string
    if not user.avatar or not user.avatar.startswith('/static/'):
        with app.app_context():
            if user.gender and user.gender.lower().startswith('m'):
                user.avatar = url_for('static', filename='avatars/male_icon.png')
            elif user.gender and user.gender.lower().startswith('f'):
                user.avatar = url_for('static', filename='avatars/female_icon.png')
            else:
                user.avatar = url_for('static', filename='avatars/neutral_icon.png')
            db.session.commit()

    latest_discussions = Discussion.query.order_by(Discussion.created_at.desc()).limit(10).all()

    # --- Client Notification Logic (FIX) ---
    client_notifications = []
    if current_user.role == 'client':
        # Fetch UNREAD notifications for the current client
        client_notifications = db.session.execute(
            db.select(Notification)
            .filter_by(client_id=current_user.id, is_read=False)
            .order_by(Notification.timestamp.desc())
        ).scalars().all()
    # --- End Client Notification Logic ---

    return render_template(
        'client_dashboard.html',
        user=user,
        discussions=latest_discussions,
        client_notifications=client_notifications,  # Passed the notifications
        hide_nav=True
    )


@app.route('/mark_notification_read/<int:notification_id>')
@login_required
def mark_notification_read(notification_id):
    # Only clients can mark their notifications as read
    if current_user.role != 'client':
        return redirect(url_for('community_dashboard'))

    notification = db.session.get(Notification, notification_id)

    # Check if notification exists and belongs to the current user
    if notification and notification.client_id == current_user.id:
        notification.is_read = True
        db.session.commit()

    # Redirect back to the page the client came from
    return redirect(url_for('community_dashboard'))


@app.route('/community/category/<category_name>')
@login_required
def view_category(category_name):
    user = current_user

    # Filter discussions by the category name passed in the URL
    filtered_discussions = Discussion.query.filter_by(category=category_name).order_by(
        Discussion.created_at.desc()).all()

    if not filtered_discussions:
        flash(f"No discussions found in the category: {category_name}.", "info")

    return render_template(
        'client_dashboard.html',
        user=user,
        discussions=filtered_discussions,
        current_category=category_name,  # Optionally pass this to highlight the category filter
        hide_nav=True
    )


@app.route('/start_discussion', methods=['GET', 'POST'])
@login_required
def create_discussion():
    user = current_user
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
@login_required
def view_discussion(discussion_id):
    discussion = Discussion.query.get_or_404(discussion_id)

    form = ReplyForm()

    if form.validate_on_submit():
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


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def profile_settings():
    user = current_user

    # 1. Profile Update Form (for username/avatar)
    profile_form = ProfileSettingsForm(obj=user)

    # 2. Password Change Form
    password_form = PasswordChangeForm()

    # --- Profile Form Submission Logic ---
    if profile_form.validate_on_submit() and profile_form.submit.data:
        if profile_form.username.data != user.username:
            if User.query.filter_by(username=profile_form.username.data).first():
                flash("That username is already taken. Please choose another.", "warning")
                # Need to pass both forms back to the template
                return render_template('settings.html', profile_form=profile_form, password_form=password_form,
                                       user=user, cache_buster=datetime.now().timestamp(), hide_nav=True)

        user.username = profile_form.username.data

        # Avatar Mapping and Saving
        selected_avatar_name = profile_form.avatar.data

        avatar_mapping = {
            'Male Icon': url_for('static', filename='images/male.png'),
            'Female Icon': url_for('static', filename='images/female.png'),
            'Neutral Icon': url_for('static', filename='images/neutral.png'),
        }

        if selected_avatar_name in avatar_mapping:
            user.avatar = avatar_mapping[selected_avatar_name]

        db.session.commit()
        flash("Profile updated successfully! ✨", "success")
        return redirect(url_for('profile_settings'))

    # --- Password Form Submission Logic ---
    if password_form.validate_on_submit() and password_form.submit_password.data:
        # 1. Check if the current password is correct
        if not check_password_hash(user.password, password_form.current_password.data):
            flash("Current password entered is incorrect.", "error")
            # Pass both forms back to the template
            return render_template('settings.html', profile_form=profile_form, password_form=password_form, user=user,
                                   cache_buster=datetime.now().timestamp(), hide_nav=True)

        # 2. Hash and update the new password
        user.password = generate_password_hash(password_form.new_password.data)
        db.session.commit()
        flash("Password changed successfully! Please log in again.", "success")
        return redirect(url_for('logout'))

    # --- Initial GET Request (Pass both forms) ---
    return render_template('settings.html',
                           profile_form=profile_form,
                           password_form=password_form,
                           user=user,
                           cache_buster=datetime.now().timestamp(),
                           hide_nav=True)


@app.route('/seed_db')
def seed_db():
    # This route is only for testing/development. DO NOT USE IN PRODUCTION.

    # Ensure a test user exists
    test_user = User.query.filter_by(email='test@client.com').first()
    if not test_user:
        test_user = User(
            email='test@client.com',
            password=generate_password_hash('password360'),
            role='client',
            username='TestUserSeed',  # CRITICAL: Ensure a unique seed username to prevent IntegrityError
            age=30,
            gender='M',
            location='TX',
            dob='01/01/1990',
        )

        if test_user.gender and test_user.gender.lower().startswith('m'):
            test_user.avatar = url_for('static', filename='avatars/male_icon.png')
        else:
            test_user.avatar = url_for('static', filename='avatars/neutral_icon.png')

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
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash("Access denied.", "error")
        return redirect(url_for('community_dashboard'))

    # Fetch users segmented by role
    clients = db.session.execute(db.select(User).filter_by(role='client')).scalars().all()
    admins = db.session.execute(db.select(User).filter_by(role='admin')).scalars().all()
    therapists = db.session.execute(db.select(User).filter_by(role='therapist')).scalars().all()

    return render_template('admin.html',
                           clients=clients,
                           admins=admins,
                           therapists=therapists,
                           hide_nav=True
                           )


@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash("You are not authorized to perform this action.", "error")
        return redirect(url_for('home'))

    user = db.session.get(User, user_id)
    if user:
        # Delete related records
        Appointment.query.filter_by(client_id=user.id).delete(synchronize_session='fetch')
        if user.role == 'therapist':
            Appointment.query.filter_by(therapist_id=user.id).update(
                {'therapist_id': None},
                synchronize_session='fetch'
            )
        Reply.query.filter_by(user_id=user.id).delete(synchronize_session='fetch')
        Discussion.query.filter_by(user_id=user.id).delete(synchronize_session='fetch')

        # Delete Notifications assigned to this user
        Notification.query.filter_by(client_id=user.id).delete(synchronize_session='fetch')

        db.session.delete(user)
        db.session.commit()

        flash("User and related data deleted successfully.", "success")
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
@login_required  # Use Flask-Login's logout helper
def logout():
    logout_user()
    session.clear()
    flash("👋 You’ve been logged out successfully.", "info")
    return redirect(url_for('home'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route('/guidelines')
@login_required
def guidelines():
    return render_template('guidelines.html', hide_nav=True)


# --- APPOINTMENT BOOKING FLOW ---

@app.route('/request_appointment', methods=['GET'])
@login_required
def request_appointment():
    # Fetch all users with the role 'therapist'
    all_therapists = db.session.execute(
        db.select(User).filter_by(role='therapist')
    ).scalars().all()

    # Generate date and time options (remains the same)
    today = date.today()
    date_options = []
    for i in range(5):
        d = today + timedelta(days=i)
        value = d.strftime('%Y-%m-%d')
        display = d.strftime('%A, %b %d')
        date_options.append((value, display))

    time_slots = ["10:00 AM", "11:30 AM", "2:00 PM", "4:30 PM", "6:00 PM"]

    # Pass the real therapist objects
    return render_template('request_appointment.html',
                           dates=date_options,
                           time_slots=time_slots,
                           available_therapists=all_therapists,
                           hide_nav=True)


@app.route('/view_appointments', methods=['GET', 'POST'])
@login_required
def view_appointments():
    preselection = None

    if request.method == 'POST':
        location = request.form.get('location')
        service_type = request.form.get('service_type')

        print(f"DEBUG: Location received: '{location}', Service received: '{service_type}'")

        # --- FIX: VALIDATION CHECK ---
        # Ensure both required fields were submitted and are not empty
        if not location or not service_type:
            # If data is missing/invalid, flash error and redirect back.
            flash("Please select both a clinic location and a service type.", "error")
            return redirect(url_for('request_appointment'))
        # --- END FIX ---

        # Data is valid, proceed to save to session
        preselection = {
            'location': location,
            'service_type': service_type
        }
        session['preselection'] = preselection
        # No need for an explicit redirect here; the function continues below.

    elif 'preselection' in session:
        # User is navigating back/refreshing, use saved session data
        preselection = session.get('preselection')

    else:
        # User navigated directly to /view_appointments without using the form
        flash("Please select a service and location first.", "warning")
        return redirect(url_for('request_appointment'))

    # If execution reaches this point, 'preselection' must contain valid data.
    service_type = preselection['service_type']  # This is now safe

    # Generate dates
    min_date = date.today().strftime('%Y-%m-%d')
    max_date_obj = date(2026, 12, 31)
    max_date = max_date_obj.strftime('%Y-%m-%d')

    available_therapists = User.query.filter_by(role='therapist').all()

    # REVISED MOCK FILTERING LOGIC
    if service_type == 'psychiatry':
        available_therapists = [t for t in available_therapists if 'Dr.' in t.username]

    if not available_therapists:
        flash(f"No providers available for {service_type} at this time. Please try a different selection.", "warning")
        return redirect(url_for('request_appointment'))

    time_slots_for_today = ["10:00 AM", "11:30 AM", "2:00 PM", "4:30 PM", "6:00 PM"]

    return render_template('view_appointments.html',
                           hide_nav=True,
                           min_date=min_date,
                           max_date=max_date,
                           available_therapists=available_therapists,
                           time_slots_for_today=time_slots_for_today,
                           location=preselection['location'],
                           service_type=preselection['service_type'])

@app.route('/appointment_review', methods=['POST'])
@login_required
def appointment_review():
    date_val = request.form.get('date')
    time = request.form.get('time')
    therapist_id = request.form.get('therapist')
    note = request.form.get('note', 'No note provided.')

    # Get the preselection details for service_type/location
    preselection = session.get('preselection', {})
    service_type = preselection.get('service_type', 'N/A')
    location = preselection.get('location', 'N/A')

    if not date_val or not time or not therapist_id:
        flash("Please select a date, time slot, and a therapist before reviewing.", "error")
        return redirect(url_for('request_appointment'))

    therapist = db.session.get(User, int(therapist_id))
    if not therapist or therapist.role != 'therapist':
        flash("Invalid therapist selected.", "error")
        return redirect(url_for('request_appointment'))

    # Save details to session temporarily, including all necessary keys
    session['booking_details'] = {
        'date': date_val,
        'time': time,
        'therapist_id': therapist_id,
        'therapist': therapist.username,
        'note': note,
        'location': location,
        'service_type': service_type
    }

    return render_template(
        'appointment_review.html',
        date=date_val,
        time=time,
        therapist=therapist.username,
        note=note,
        location=location,
        service_type=service_type,
        hide_nav=True,
        user=current_user
    )


@app.route('/confirm_appointment', methods=['POST'])
@login_required
def confirm_appointment():
    booking_details = session.pop('booking_details', None)

    if not booking_details:
        flash("Appointment details lost. Please start booking again.", "error")
        return redirect(url_for('request_appointment'))

    therapist_id_str = booking_details.get('therapist_id')
    if not therapist_id_str:
        flash("Therapist information missing. Please re-book.", "error")
        return redirect(url_for('request_appointment'))

    therapist = db.session.get(User, int(therapist_id_str))

    # --- Database Save (Keep this section) ---
    new_appointment = Appointment(
        client_id=current_user.id,
        therapist_id=therapist.id,
        date=booking_details['date'],
        time=booking_details['time'],
        note=booking_details['note'],
        service_type=booking_details['service_type'],
        status='Pending'
    )

    db.session.add(new_appointment)
    db.session.commit()
    # --- END Database Save ---

    location_map = {
        'MC': 'Makati City, MC',
        'Manda': 'Mandaluyong, Manda',
        'TC': 'Taguig City, TC',
    }

    location_code = booking_details.get('location')

    clinic_location = location_map.get(location_code, 'Unknown Location')

    therapist_display_name = f"Dr. {therapist.username}"

    # 3. Create the final session data to pass to the success page
    session['final_booking_details'] = {
        'date': booking_details['date'],
        'time': booking_details['time'],
        'service_type': booking_details['service_type'],
        # Use the display name and location for the success page!
        'therapist': therapist_display_name,
        'location': clinic_location
    }

    # Flash message should use the display name
    flash(
        f"Appointment requested for {booking_details['date']} at {booking_details['time']} with {therapist_display_name}. Awaiting approval.",
        "success")

    return redirect(url_for('appointment_success'))

@app.route('/appointment_success')
@login_required
def appointment_success():
    # 1. Retrieve the final, confirmed booking details from the session
    booking_details = session.pop('final_booking_details', None)

    # 2. Handle case where session details are missing (direct navigation or refresh after pop)
    if not booking_details:
        flash("Booking details not found. Please check your dashboard for confirmation.", "warning")
        return redirect(url_for('community_dashboard'))  # FIX: Use correct endpoint

    # 3. Render the template, passing the complete dictionary
    return render_template('appointment_success.html',
                           booking_details=booking_details,
                           hide_nav=True)


# --- NEW ROUTE for Viewing Appointments ---
@app.route('/my_appointments')
@login_required
def my_appointments():
    # Fetch appointments for the current user, ordered by date and time
    user_appointments = db.session.execute(
        db.select(Appointment)
        .filter_by(client_id=current_user.id)
        .order_by(Appointment.date, Appointment.time)
    ).scalars().all()

    return render_template('my_appointments.html',
                           appointments=user_appointments,
                           hide_nav=True)


# --- THERAPIST DASHBOARD ROUTES ---

@app.route('/therapist_dashboard')
@login_required
def therapist_dashboard():
    # 1. Authorization: Only therapists can view this
    if current_user.role != 'therapist':
        flash("Access denied. You must be a therapist to access this dashboard.", "error")
        return redirect(url_for('home'))

    # 2. Fetch appointments assigned to the CURRENTLY logged-in therapist
    assigned_appointments = db.session.execute(
        db.select(Appointment)
        .filter_by(therapist_id=current_user.id)  # Filter by the therapist's own ID
        .order_by(Appointment.date, Appointment.time)
    ).scalars().all()

    # 3. Pass appointments AND the user object to the template
    return render_template('therapist_dashboard.html',
                           user=current_user,  # FIX: Passes the user object to the template
                           appointments=assigned_appointments,
                           hide_nav=True)


@app.route('/update_appointment_status/<int:appointment_id>/<string:new_status>', methods=['POST'])
@login_required
def update_appointment_status(appointment_id, new_status):
    # Authorization: Ensure only therapists can manage appointments
    if current_user.role != 'therapist':
        flash("Authorization failed.", "danger")
        return redirect(url_for('home'))

    # Input Validation
    if new_status not in ['Accepted', 'Rejected']:
        flash("Invalid status change requested.", "danger")
        return redirect(url_for('therapist_dashboard'))

    # Fetch the appointment
    appointment = db.session.get(Appointment, appointment_id)

    if not appointment:
        flash("Appointment not found.", "danger")
        return redirect(url_for('therapist_dashboard'))

    # Security Check: Ensure the appointment belongs to the current therapist
    if appointment.therapist_id != current_user.id:
        flash("You are not authorized to manage this appointment.", "danger")
        return redirect(url_for('therapist_dashboard'))

    # Check if status is already finalized
    if appointment.status != 'Pending':
        flash(f"Appointment is already {appointment.status}.", "warning")
        return redirect(url_for('therapist_dashboard'))

    # Update status
    appointment.status = new_status

    # --- CLIENT NOTIFICATION CREATION ---
    if new_status == 'Accepted':
        client_message = (
            f"✅ Success! Your appointment for {appointment.service_type} with Dr. {current_user.username} on "
            f"{appointment.date} at {appointment.time} has been **CONFIRMED**."
        )
        client_category = 'success'
    else:  # new_status == 'Rejected'
        client_message = (
            f"❌ Notice: Your request for {appointment.service_type} with Dr. {current_user.username} "
            f"on {appointment.date} at {appointment.time} has been **REJECTED**."
        )
        client_category = 'danger'

    # Create the new notification record
    notification = Notification(
        client_id=appointment.client_id,
        message=client_message,
        category=client_category,
        timestamp=datetime.utcnow()
    )
    db.session.add(notification)
    # --- END CLIENT NOTIFICATION CREATION ---

    db.session.commit()

    flash(f"Appointment with {appointment.client.username} successfully {new_status}.", "success")
    return redirect(url_for('therapist_dashboard'))


# --- NEW ROUTE for Client Appointment Cancellation ---

@app.route('/cancel_appointment/<int:appointment_id>', methods=['POST'])
@login_required
def cancel_appointment(appointment_id):
    appointment = db.session.get(Appointment, appointment_id)

    if not appointment:
        return jsonify({'success': False, 'message': 'Appointment not found.'}), 404

    # Critical Security Check: Ensure the appointment belongs to the current user (client)
    if appointment.client_id != current_user.id:
        return jsonify({'success': False, 'message': 'Authorization denied.'}), 403

    # Check if the appointment is already finalized (Rejected/Cancelled)
    if appointment.status in ['Rejected', 'Cancelled']:
        return jsonify({'success': False, 'message': 'Appointment is already finalized.'}), 400

    appointment.status = 'Cancelled'
    db.session.commit()

    flash("Your appointment has been successfully cancelled.", "success")

    return jsonify({
        'success': True,
        'message': 'Appointment cancelled.',
    })


# --- ADMIN ADD THERAPIST ROUTE ---
# FIX: The following block was incomplete/missing in the provided code, but the function name was mentioned.
# This provides a basic functional version.
@app.route('/admin/add_therapist', methods=['GET', 'POST'])
@login_required
def admin_add_therapist():
    if current_user.role != 'admin':
        flash("Access denied.", "error")
        return redirect(url_for('community_dashboard'))

    form = AddTherapistForm()

    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("Email already registered.", "warning")
            return render_template('admin_add_therapist.html', form=form, hide_nav=True)

        hashed_pw = generate_password_hash(form.password.data)

        new_therapist = User(
            email=form.email.data,
            password=hashed_pw,
            role='therapist',
            username=form.username.data,
            # Therapist specific fields like specialization can be added here
        )
        db.session.add(new_therapist)
        db.session.commit()

        flash(f"Therapist {new_therapist.username} added successfully!", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('add_therapist.html', form=form, hide_nav=True)


# app.py

# ... existing code ...

@app.route('/therapist_settings', methods=['GET', 'POST'])
@login_required
@role_required('therapist')
def therapist_settings():
    user = current_user

    # 1. Profile Update Form (using the existing form)
    profile_form = ProfileSettingsForm(obj=user)

    # 2. Password Change Form
    password_form = PasswordChangeForm()

    # --- Profile Form Submission Logic ---
    if profile_form.validate_on_submit() and profile_form.submit.data:
        if profile_form.username.data != user.username:
            if User.query.filter_by(username=profile_form.username.data).first():
                flash("That username is already taken. Please choose another.", "warning")
                # Return template with both forms if validation fails
                return render_template('therapist_settings.html',
                                       profile_form=profile_form,
                                       password_form=password_form,
                                       user=user,
                                       cache_buster=datetime.now().timestamp(),
                                       hide_nav=True)

        user.username = profile_form.username.data

        # Avatar Mapping and Saving (copied from client logic)
        selected_avatar_name = profile_form.avatar.data
        avatar_mapping = {
            'Male Icon': url_for('static', filename='avatars/male_icon.png'),
            'Female Icon': url_for('static', filename='avatars/female_icon.png'),
            'Neutral Icon': url_for('static', filename='avatars/neutral_icon.png'),
        }
        if selected_avatar_name in avatar_mapping:
            user.avatar = avatar_mapping[selected_avatar_name]

        db.session.commit()
        flash("Profile updated successfully! ✨", "success")
        return redirect(url_for('therapist_settings'))

    # --- Password Form Submission Logic ---
    if password_form.validate_on_submit() and password_form.submit_password.data:
        # 1. Check if the current password is correct
        if not check_password_hash(user.password, password_form.current_password.data):
            flash("Current password entered is incorrect.", "error")
            # Return template with both forms if validation fails
            return render_template('therapist_settings.html',
                                   profile_form=profile_form,
                                   password_form=password_form,
                                   user=user,
                                   cache_buster=datetime.now().timestamp(),
                                   hide_nav=True)

        # 2. Hash and update the new password
        user.password = generate_password_hash(password_form.new_password.data)
        db.session.commit()
        flash("Password changed successfully! Please log in again.", "success")
        return redirect(url_for('logout'))

    # --- Initial GET Request or Form Re-render ---
    return render_template('therapist_settings.html',
                           profile_form=profile_form,
                           password_form=password_form,
                           user=user,
                           cache_buster=datetime.now().timestamp(),
                           hide_nav=True)
if __name__ == '__main__':
    # Initialize the database and create tables if they don't exist
    with app.app_context():
        db.create_all()
    app.run(debug=True)