# forms.py

from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, BooleanField, SubmitField, PasswordField, IntegerField
# --- UPDATED IMPORTS ---
from wtforms.validators import DataRequired, Email, Length, InputRequired, EqualTo, NumberRange # <-- ADDED NumberRange


# --- 1. RegisterForm (for Page 1: Patient Info) ---
class RegisterForm(FlaskForm):
    # Field 1: Email Address
    email = StringField('Patient or Parent/Guardian Email Address',
                        validators=[DataRequired(message="Email is required."),
                                    Email(message="Must be a valid email address.")])

    # Field 2: Location (using a SelectField for the dropdown)
    location = SelectField('Patient Location',
                           choices=[
                               ('', 'Select State'),  # Empty initial choice
                               ('NY', 'New York'),
                               ('CA', 'California'),
                               ('TX', 'Texas'),
                               ('FL', 'Florida'),
                               # Add more states here as needed
                           ],
                           validators=[DataRequired(message="Location is required.")])

    # Field 3: Date of Birth
    dob = StringField('Patient Date of Birth',
                      validators=[DataRequired(message="Date of Birth is required."),
                                  Length(min=10, max=10,
                                         message="Format must be MM/DD/YYYY (10 characters).")])

    # Checkboxes for Interested Services (BooleanFields)
    therapy_services = BooleanField('Therapy services (18+)')
    psychiatry_management = BooleanField('Psychiatry/medication management (12+)')
    substance_counseling = BooleanField('Substance use counseling/medication-assisted addiction treatment (18+)')
    not_sure = BooleanField("I'm not sure")

    # Checkbox for CAPTCHA placeholder (I am human)
    i_am_human = BooleanField('I am human',
                              validators=[InputRequired(message="Please check the 'I am human' box.")])

    # Submit Button
    submit = SubmitField('Continue')


# --- 2. AccountForm (for Page 2: Account Creation) ---
class AccountForm(FlaskForm):
    ### Account Fields ###
    password = PasswordField('Password',
                             validators=[
                                 DataRequired(message="Password is required."),
                                 # ENHANCED: Minimum length to 10 for better security
                                 Length(min=10, message="Password must be at least 10 characters long.")
                             ])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(message="Please confirm your password."),
                                                 EqualTo('password', message='Passwords must match.')])

    ### Profile Fields ###
    age = IntegerField('Your Age',
                       validators=[
                           DataRequired(message="Age is required."),
                           # ENHANCED: Limits age range to prevent unrealistic entries
                           NumberRange(min=1, max=120, message="Please enter a realistic age between 1 and 120.")
                       ])

    gender = SelectField('Your Gender',
                         choices=[('M', 'Male'), ('F', 'Female'), ('O', 'Other')],
                         validators=[DataRequired(message="Please select your gender.")])

    submit = SubmitField('Sign Up')