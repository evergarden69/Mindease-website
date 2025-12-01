from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
import random
import os
from flask_login import login_required, current_user
from datetime import datetime, timedelta, date
from flask_migrate import Migrate
import pickle

from flask_login import LoginManager, UserMixin, current_user, login_required
from forms import RegisterForm, AccountForm, DiscussionForm, ReplyForm, ProfileSettingsForm, PasswordChangeForm, AddTherapistForm # <-- MAKE SURE TO IMPORT ADDTHERAPISTFORM
from werkzeug.security import generate_password_hash, check_password_hash
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

    status = db.Column(db.String(20), default='Pending', nullable=False)  # 'Pending', 'Accepted', 'Rejected'

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


# --- CRITICAL FIX: Add user_loader callback for Flask-Login ---
@login_manager.user_loader
def load_user(user_id):
    # This must return the User object for the given user_id or None
    return db.session.get(User, int(user_id))


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

            # FIX: flask-login requires login_user to actually log the user in
            from flask_login import login_user
            login_user(user)

            flash(f"Welcome back, {user.role.capitalize()}!", "success")

            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'therapist': # Redirect therapist to their dashboard
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

        # --- FIX: Use url_for directly in the route for initial avatar setting ---
        if new_user.gender and new_user.gender.lower().startswith('m'):
            new_user.avatar = url_for('static', filename='avatars/male_icon.png')
        elif new_user.gender and new_user.gender.lower().startswith('f'):
            new_user.avatar = url_for('static', filename='avatars/female_icon.png')
        else:
            new_user.avatar = url_for('static', filename='avatars/neutral_icon.png')
        # --- END FIX ---

        db.session.add(new_user)
        db.session.commit()

        flash("Account created! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register_account.html', form=form)


@app.route('/community')
@login_required
def community_dashboard():
    # current_user is now available because of @login_required
    user = current_user

    # Check and update the avatar URL from the database if the current URL is just the filename string
    if not user.avatar.startswith('/static/'):
        with app.app_context():
            if user.gender and user.gender.lower().startswith('m'):
                user.avatar = url_for('static', filename='avatars/male_icon.png')
            elif user.gender and user.gender.lower().startswith('f'):
                user.avatar = url_for('static', filename='avatars/female_icon.png')
            else:
                user.avatar = url_for('static', filename='avatars/neutral_icon.png')
            db.session.commit()

    latest_discussions = Discussion.query.order_by(Discussion.created_at.desc()).limit(10).all()

    return render_template(
        'client_dashboard.html',
        user=user,
        discussions=latest_discussions,
        hide_nav=True
    )


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

    # 2. Password Change Form (Note: This form is not currently visible in settings.html based on your last provided template)
    password_form = PasswordChangeForm()

    # --- Profile Form Submission Logic (Checks for the specific submit button data) ---
    if profile_form.validate_on_submit() and profile_form.submit.data:
        if profile_form.username.data != user.username:
            if User.query.filter_by(username=profile_form.username.data).first():
                flash("That username is already taken. Please choose another.", "warning")
                # Need to pass both forms back to the template
                return render_template('settings.html', profile_form=profile_form, password_form=password_form,
                                       user=user, cache_buster=datetime.now().timestamp())

        user.username = profile_form.username.data

        # --- NEW FIX: Avatar Mapping and Saving ---
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
        return redirect(url_for('profile_settings'))

    # --- Password Form Submission Logic (Kept for completeness) ---
    if password_form.validate_on_submit() and password_form.submit_password.data:
        # 1. Check if the current password is correct
        if not check_password_hash(user.password, password_form.current_password.data):
            flash("Current password entered is incorrect.", "error")
            # Pass both forms back to the template
            return render_template('settings.html', profile_form=profile_form, password_form=password_form, user=user,
                                   cache_buster=datetime.now().timestamp())

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

        # --- FIX: Use url_for directly in the route for initial avatar setting ---
        if test_user.gender and test_user.gender.lower().startswith('m'):
            test_user.avatar = url_for('static', filename='avatars/male_icon.png')
        elif test_user.gender and test_user.gender.lower().startswith('f'):
            test_user.avatar = url_for('static', filename='avatars/female_icon.png')
        else:
            test_user.avatar = url_for('static', filename='avatars/neutral_icon.png')
        # --- END FIX ---

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
        return redirect(url_for('dashboard'))

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
    # Use current_user for authorization checks
    if current_user.role != 'admin':
        flash("You are not authorized to perform this action.", "error")
        return redirect(url_for('home'))

    user = User.query.get(user_id)
    if user:
        # Before deleting the user, delete related records.

        # 1. DELETE APPOINTMENTS REQUESTED BY THIS USER (CLIENT)
        # Use 'client_id' as defined in your Appointment model
        Appointment.query.filter_by(client_id=user.id).delete(synchronize_session='fetch')

        # 2. CLEAR APPOINTMENTS ASSIGNED TO THIS USER (THERAPIST)
        # If the user is a therapist, clear their ID from assigned appointments
        if user.role == 'therapist':
            Appointment.query.filter_by(therapist_id=user.id).update(
                {'therapist_id': None},
                synchronize_session='fetch'
            )

        # 3. DELETE RELATED REPLIES
        Reply.query.filter_by(user_id=user.id).delete(synchronize_session='fetch')

        # 4. DELETE RELATED DISCUSSIONS
        Discussion.query.filter_by(user_id=user.id).delete(synchronize_session='fetch')

        # Delete the user itself
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
    from flask_login import logout_user
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

# app.py (Updated request_appointment route to fetch real therapists)
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
                           available_therapists=all_therapists, # <-- NOW USING REAL USERS
                           hide_nav=True)
@app.route('/view_appointments', methods=['GET', 'POST'])
@login_required
def view_appointments():
    # 1. Handle POST Request (Data comes from request_appointment.html)
    if request.method == 'POST':
        # Retrieve and save the location and service type to the session
        location = request.form.get('location')
        service_type = request.form.get('service_type')

        if location and service_type:
            session['booking_preselection'] = {
                'location': location,
                'service_type': service_type
            }
        else:
            flash("Please select both a location and a service type.", "error")
            return redirect(url_for('request_appointment'))

    # 2. Check if pre-selection data exists (if arriving via GET or via POST)
    preselection = session.get('booking_preselection')
    if not preselection:
        flash("Please select a location and service type first.", "error")
        return redirect(url_for('request_appointment'))

    # 3. Define Date Constraints
    min_date = date.today().strftime('%Y-%m-%d')
    max_date_obj = date(2026, 12, 31)  # Example for max date
    max_date = max_date_obj.strftime('%Y-%m-%d')

    # 4. Mock Data for Therapists (Filtered by service_type)
    if preselection['service_type'] == 'therapy':
        available_therapists = [{'id': 1, 'name': 'Dr. Alice Smith (Therapy)'}]
    elif preselection['service_type'] == 'psychiatry':
        available_therapists = [{'id': 2, 'name': 'Mr. Bob Johnson (Psychiatry)'}]
    elif preselection['service_type'] == 'substance':
        available_therapists = [{'id': 3, 'name': 'Ms. Clara Lee (Substance Counseling)'}]
    else:
        available_therapists = [{'id': 99, 'name': 'Unknown Provider'}]

        # 5. Mock Time Slots
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
    therapist_id = request.form.get('therapist') # This is the ID now, not a display name
    note = request.form.get('note', 'No note provided.')

    # Server-side validation check
    if not date_val or not time or not therapist_id:
        flash("Please select a date, time slot, and a therapist before reviewing.", "error")
        return redirect(url_for('request_appointment'))

    # Fetch the actual therapist user object using the ID
    therapist = db.session.get(User, int(therapist_id))
    if not therapist or therapist.role != 'therapist':
        flash("Invalid therapist selected.", "error")
        return redirect(url_for('request_appointment'))

    # Save details to session temporarily, including the ID
    session['booking_details'] = {
        'date': date_val,
        'time': time,
        'therapist_id': therapist_id, # <-- CRITICAL: Save the ID
        'therapist': therapist.username, # Save the username for display
        'note': note
    }

    return render_template(
        'appointment_review.html',
        date=date_val,
        time=time,
        therapist=therapist.username, # Use username for display
        note=note,
        hide_nav=True,
        user=current_user
    )


# app.py (REPLACE existing /confirm_appointment route)

@app.route('/confirm_appointment', methods=['POST'])
@login_required
def confirm_appointment():
    booking_details = session.pop('booking_details', None)

    if not booking_details:
        flash("Appointment details lost. Please start booking again.", "error")
        return redirect(url_for('request_appointment'))

    # The booking details dictionary must now contain the therapist_id (a string ID)
    therapist_id_str = booking_details.get('therapist_id')

    if not therapist_id_str:
        flash("Therapist information missing. Please re-book.", "error")
        return redirect(url_for('request_appointment'))

    therapist = db.session.get(User, int(therapist_id_str))

    # Save the confirmed appointment to the database
    new_appointment = Appointment(
        client_id=current_user.id,  # Save client_id (The one who booked)
        therapist_id=therapist.id,  # Save therapist_id
        date=booking_details['date'],
        time=booking_details['time'],
        note=booking_details['note'],
        status='Pending'  # Default status
    )

    db.session.add(new_appointment)
    db.session.commit()

    flash(
        f"Appointment requested for {booking_details['date']} at {booking_details['time']} with {therapist.username}. Awaiting approval.",
        "success")
    return redirect(url_for('my_appointments'))

@app.route('/appointment_success', methods=['GET', 'POST'])  # <--- ADDED methods=['GET', 'POST']
@login_required
def appointment_success():
    # 1. Retrieve the booking details saved in the session
    booking_details = session.pop('booking_details', None)
    preselection = session.pop('booking_preselection', None)

    # 2. Add real booking logic here (e.g., saving to database, sending email)

    # 3. Handle case where session details are missing (direct navigation)
    if not booking_details or not preselection:
        flash("Booking details not found. Please start a new appointment.", "warning")
        return redirect(url_for('request_appointment'))

    # Combine data for success page display
    all_details = {**preselection, **booking_details}

    return render_template('appointment_success.html',
                           date=all_details['date'],
                           time=all_details['time'],
                           location=all_details['location'],
                           hide_nav=True)
# --- NEW ROUTE for Viewing Appointments ---
@app.route('/my_appointments')
@login_required
def my_appointments():
    # Fetch appointments for the current user, ordered by date and time
    user_appointments = db.session.execute(
        db.select(Appointment)
        .filter_by(client_id=current_user.id) # <-- FIX: Check client_id, not user_id
        # NOTE: Sorting by string date/time can be unreliable. For production, use datetime objects.
        .order_by(Appointment.date, Appointment.time)
    ).scalars().all()

    return render_template('my_appointments.html',
                           appointments=user_appointments,
                           hide_nav=True)

# --- FIX: Renamed function to match 'admin_add_therapist' endpoint and use new form/template ---
@app.route('/admin/add_therapist', methods=['GET', 'POST'])
@login_required
def admin_add_therapist(): # <-- Renamed to match the url_for() call!
    if current_user.role != 'admin':
        flash("Access denied.", "error")
        return redirect(url_for('home'))

    # Use the simple form for adding a therapist (must be defined in forms.py and imported!)
    form = AddTherapistForm()

    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("Email already registered.", "warning")
            # Render the simple add_therapist.html template on failure
            return render_template('add_therapist.html', form=form, title="Add Therapist", hide_nav=True)

        # Check for unique username
        if User.query.filter_by(username=form.username.data).first():
            flash("That username is already taken. Please choose another.", "warning")
            return render_template('add_therapist.html', form=form, title="Add Therapist", hide_nav=True)

        hashed_pw = generate_password_hash(form.password.data)

        new_therapist = User(
            email=form.email.data,
            password=hashed_pw,
            username=form.username.data,
            role='therapist',
            # Use placeholders for non-essential client fields
            age=99, gender='N/A', location='HQ',
            avatar=url_for('static', filename='avatars/professional_icon.png') # Use a professional avatar
        )

        db.session.add(new_therapist)
        db.session.commit()

        flash(f"Therapist '{form.username.data}' created successfully!", "success")
        return redirect(url_for('admin_dashboard'))

    # Use the new, simple template for the form
    return render_template('add_therapist.html', form=form, title="Add New Therapist", hide_nav=True)
# --- END FIX ---


# app.py (NEW Therapist Dashboard Route)
@app.route('/therapist_dashboard')
@login_required
def therapist_dashboard():
    # Authorization: Only therapists can view this
    if current_user.role != 'therapist':
        flash("Access denied. You must be a therapist to access this dashboard.", "error")
        return redirect(url_for('home'))

    # Fetch all appointments assigned to the current therapist
    # Order by status (to show Pending appointments first), then by date/time
    therapist_appointments = db.session.execute(
        db.select(Appointment)
        .filter_by(therapist_id=current_user.id)
        .order_by(Appointment.status.desc(), Appointment.date, Appointment.time)
    ).scalars().all()

    return render_template('therapist_dashboard.html',
                           appointments=therapist_appointments,
                           user=current_user,
                           hide_nav=True)


# app.py (NEW Route to Update Appointment Status)
@app.route('/appointment/update_status/<int:appointment_id>/<string:new_status>', methods=['POST'])
@login_required
def update_appointment_status(appointment_id, new_status):
    # 1. Authorization Check
    if current_user.role != 'therapist':
        flash("You are not authorized to perform this action.", "error")
        return redirect(url_for('home'))

    appointment = db.session.get(Appointment, appointment_id)

    # 2. Validation Checks
    if not appointment:
        flash("Appointment not found.", "error")
        return redirect(url_for('therapist_dashboard'))

    # Ensure the therapist is only managing their own appointments
    if appointment.therapist_id != current_user.id:
        flash("You are not authorized to manage this appointment.", "error")
        return redirect(url_for('therapist_dashboard'))

    valid_statuses = ['Accepted', 'Rejected']
    if new_status not in valid_statuses:
        flash("Invalid status provided.", "error")
        return redirect(url_for('therapist_dashboard'))

    # 3. Update Status and Commit
    appointment.status = new_status
    db.session.commit()

    flash(f"Appointment status updated to '{new_status}' successfully.", "success")
    return redirect(url_for('therapist_dashboard'))


if __name__ == '__main__':
    with app.app_context():
        # db.drop_all() # ONLY use this if you want to wipe the database
        db.create_all()
    app.run(debug=True)