import os
from flask_wtf import CSRFProtect, FlaskForm
from flask_jwt_extended import jwt_required, get_jwt_identity
from wtforms.validators import DataRequired, Email, EqualTo,Length,ValidationError,Optional,Regexp
from flask_wtf.csrf import generate_csrf
from wtforms import SubmitField
from wtforms import StringField, SubmitField, FloatField,PasswordField,SelectField
from wtforms.validators import DataRequired
from flask import Flask, render_template, request, redirect, url_for, flash,jsonify, abort,session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin,login_manager,current_user
from Crypto.Hash import SHA256
from flask_migrate import Migrate
from werkzeug.datastructures import MultiDict
from alembic import op
from flask_wtf.csrf import CSRFError
import sqlalchemy as sa
from functools import wraps
import pymysql, logging


# from utils import load_config, generate_db_uri
 

# from app import User, Admin  # Ensure these are imported from your app
#pip install pycryptodome
# from pycryptodome.Hash import *

import pandas as pd
import joblib
import pickle, sqlite3
import random, time
from datetime import timedelta


app = Flask(__name__)


#sqlite3 flask default db
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'


#connecting to an external database.
# Store database credentials in environment variables
# app.config['SECRET_KEY'] = 'english92'
# app.config['SQLALCHEMY_DATABASE_URI'] = generate_db_uri()
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
#     "pool_pre_ping": True,
#     "pool_recycle": 250
# }

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
csrf.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


#10 digit codes for the prediction aprroval page

def generate_unique_code():
    return random.randint(1000000000, 9999999999)


class DeleteUserForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Delete User')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

    @classmethod
    def from_json(cls, data):
        # Implement logic to create a LoginForm object from JSON data
        # For example:
        email = data.get('email')
        password = data.get('password')
        return cls(email=email, password=password)
    


class RegistrationForm(FlaskForm):
    class Meta:
        csrf = False
    business_name = StringField('Business Name', validators=[DataRequired(), Length(min=10, max=100)])
    business_address = StringField('Business Address', validators=[DataRequired(), Length(min=10, max=100)])
    phone_number = StringField('Phone Number', validators=[DataRequired(), Length(max=15), Regexp(regex='^\d+$', message="Phone number must contain only digits")])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=100)])
    state = SelectField('State', choices=[
        ('Abia', 'Abia'), ('Adamawa', 'Adamawa'), ('Akwa Ibom', 'Akwa Ibom'), 
        ('Anambra', 'Anambra'), ('Bauchi', 'Bauchi'), ('Bayelsa', 'Bayelsa'), 
        ('Benue', 'Benue'), ('Borno', 'Borno'), ('Cross River', 'Cross River'), 
        ('Delta', 'Delta'), ('Ebonyi', 'Ebonyi'), ('Edo', 'Edo'), ('Ekiti', 'Ekiti'), 
        ('Enugu', 'Enugu'), ('Gombe', 'Gombe'), ('Imo', 'Imo'), ('Jigawa', 'Jigawa'), 
        ('Kaduna', 'Kaduna'), ('Kano', 'Kano'), ('Katsina', 'Katsina'), ('Kebbi', 'Kebbi'), 
        ('Kogi', 'Kogi'), ('Kwara', 'Kwara'), ('Lagos', 'Lagos'), ('Nasarawa', 'Nasarawa'), 
        ('Niger', 'Niger'), ('Ogun', 'Ogun'), ('Ondo', 'Ondo'), ('Osun', 'Osun'), 
        ('Oyo', 'Oyo'), ('Plateau', 'Plateau'), ('Rivers', 'Rivers'), ('Sokoto', 'Sokoto'), 
        ('Taraba', 'Taraba'), ('Yobe', 'Yobe'), ('Zamfara', 'Zamfara'), ('FCT', 'FCT')
    ], validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    business_project = StringField('Business Project', validators=[Optional(), Length(max=100)])
    value_chain_cat = StringField('Value Chain Category', validators=[Optional(), Length(max=100)])
    borrowing_relationship = StringField('Borrowing Relationship', validators=[Optional(), Length(max=100)])
    fresh_loan_request = StringField('Fresh Loan Request', validators=[Optional(), Length(max=100)])
    request_submitted_to_bank = StringField('Request Submitted to Bank', validators=[Optional(), Length(max=100)])
    feasibility_study_available = StringField('Feasibility Study Available', validators=[Optional(), Length(max=100)])
    proposed_facility_amount = FloatField('Proposed Facility Amount', validators=[Optional()])
    purpose_of_facility = StringField('Purpose of Facility', validators=[Optional(), Length(max=255)])
    name_of_bank = StringField('Name of Bank', validators=[Optional(), Length(max=255)])
    security_proposed = StringField('Security Proposed', validators=[Optional(), Length(max=255)])
    highlights_of_discussion = StringField('Highlights of Discussion', validators=[Optional()])
    rm_bm_name_phone_number = StringField('RM/BM Name and Phone Number', validators=[Optional(), Length(max=100)])
    rm_bm_email = StringField('RM/BM Email', validators=[Optional(), Email(), Length(max=100)])
    status_update = StringField('Status Update', validators=[Optional()])
    challenges = StringField('Challenges', validators=[Optional()])
    proposed_next_steps = StringField('Proposed Next Steps', validators=[Optional()])
    submit = SubmitField('Register')


def validate_email(self, field):
        if not field.data.endswith('@nrs.com'):
            raise ValidationError('Email must have the domain "@nrs.com".')

class RegisterAdminForm(FlaskForm):
    admin_name = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
    admin_address = StringField('Address', validators=[DataRequired(), Length(min=2, max=100)])
    phone_number = StringField('Phone Number', validators=[DataRequired(), Length(max=15), Regexp(regex='^\d+$', message="Phone number must contain only digits")])
    email = StringField('Email', validators=[DataRequired(), Email(), validate_email])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')


#logged out session................
@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=10)
    session.modified = True
    session['last_activity'] = time.time()

@app.route('/check_activity', methods=['POST'])
def check_activity():
    if 'last_activity' in session:
        last_activity = session['last_activity']
        current_time = time.time()
        if current_time - last_activity > 600:
            session.clear()
            return jsonify({'message': 'Session expired due to inactivity'}), 401
    return jsonify({'message': 'Activity checked'}), 200


#wrapper................for login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You need to be logged in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


#wrapper................for admin login
# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

   

#The User class defines the database model.

class User(UserMixin, db.Model):

    id = db.Column(db.Integer, primary_key=True)
    business_name = db.Column(db.String(150), nullable=False)
    business_address = db.Column(db.String(150), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    state = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    prediction_id = db.Column(db.String(36), unique=True, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    
    #prediction section columns....
    business_project = db.Column(db.String(150), nullable=True)
    value_chain_cat = db.Column(db.String(150), nullable=True)
    borrowing_relationship = db.Column(db.String(10), nullable=True)
    fresh_loan_request = db.Column(db.String(15), nullable=True)
    request_submitted_to_bank = db.Column(db.String(10), nullable=True)
    feasibility_study_available = db.Column(db.String(10), nullable=True)
    proposed_facility_amount = db.Column(db.Float(20), nullable=True)

    #other data to be provided updates by officer 

    purpose_of_facility = db.Column(db.String(255), nullable=True)
    name_of_bank = db.Column(db.String(100), nullable=True)
    security_proposed = db.Column(db.String(100), nullable=True)
    highlights_of_discussion = db.Column(db.Text)
    rm_bm_name_phone_number = db.Column(db.String(100), nullable=True)
    rm_bm_email = db.Column(db.String(100), nullable=True)
    status_update = db.Column(db.Text)
    challenges = db.Column(db.Text)
    proposed_next_steps = db.Column(db.Text)


class SearchForm(FlaskForm):
    search_term = StringField('Search Term', validators=[DataRequired()])
    submit = SubmitField('Search')


class Admin(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    admin_name = db.Column(db.String(150), nullable=False)
    admin_address = db.Column(db.String(150), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)


class PredictionForm(FlaskForm):
    BUSINESS_PROJECT = SelectField('Business Project', choices=[ ('NEW', 'Fresh'), ('EXISTING', 'Existing')], validators=[DataRequired()])
    VALUE_CHAIN_CATEGORY = SelectField('Value Chain Category', choices=[('PRE-UPSTREAM', 'Pre-Upstream'), ('UPSTREAM', 'Upstream'),('MIDSTREAM', 'Midstream'), ('DOWNSTREAM', 'Downstream')], validators=[DataRequired()])
    BORROWING_RELATIONSHIP = SelectField('Borrowing Relationship', choices=[ ('NO', 'No'), ('YES', 'Yes')], validators=[DataRequired()])
    FRESH_LOAN_REQUEST = SelectField('Fresh Loan Request', choices=[('NO', 'No'), ('YES', 'Yes')], validators=[DataRequired()])
    REQUEST_SUBMITTED_TO_BANK = SelectField('Request Submitted to Bank', choices=[('NO', 'No'), ('YES', 'Yes')], validators=[DataRequired()])
    FEASIBILITY_STUDY_AVAILABLE = SelectField('Feasibility Study Available', choices=[('NO', 'No'), ('YES', 'Yes'), ('NIL', 'Not Available')], validators=[DataRequired()])
    PROPOSED_FACILITY_AMOUNT = FloatField('Proposed Facility Amount', validators=[DataRequired()])
    submit = SubmitField('Predict')


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    form = PredictionForm()
    user = User.query.get_or_404(user_id)
    
    # Check if current user is admin
    if not session['is_admin']:
        abort(403)  # Forbidden

    if request.method == 'POST':

        # Update user information by admin officer
        user.PURPOSE_OF_FACILITY = request.form.get('purpose_of_facility')
        user.NAME_OF_BANK = request.form.get('name_of_bank') 
        user.SECURITY_PROPOSED = request.form.get('security_proposed') 
        user.HIGHLIGHTS_OF_DISCUSSION = request.form.get('highlights_of_discussion') 
        user.RM_BM_NAME_PHONE_NUMBER = request.form.get('rm_bm_name_phone_number') 
        user.RM_BM_EMAIL = request.form.get('rm_bm_email') 
        user.STATUS_UPDATE = request.form.get('status_update') 
        user.CHALLENGES = request.form.get('challenges') 
        user.PROPOSED_NEXT_STEPS = request.form.get('proposed_next_steps') 


        # Level 2 (registration page)
        user.business_name = request.form.get('business_name') or None
        user.business_address = request.form.get('business_address') or None
        user.phone_number = request.form.get('phone_number') or None
        user.email = request.form.get('email') or None
        user.state = request.form.get('state') or None
        password = request.form.get('password')
        if password:
            user.password = generate_password_hash(password)


        # Level 3 (prediction page)
        user.business_project = request.form.get('business_project') or None
        user.value_chain_cat = request.form.get('value_chain_cat') or None
        user.borrowing_relationship = request.form.get('borrowing_relationship') or None
        user.fresh_loan_request = request.form.get('fresh_loan_request') or None
        user.request_submitted_to_bank = request.form.get('request_submitted_to_bank') or None
        user.feasibility_study_available = request.form.get('feasibility_study_available') or None
        user.proposed_facility_amount = request.form.get('proposed_facility_amount') or 0.00
        if user.proposed_facility_amount:
            try:
                user.proposed_facility_amount = float(user.proposed_facility_amount)
            except ValueError:
                flash('Proposed facility amount must be a number.', 'danger')
                return render_template('edit_user.html', user=user,form=form)
        
        # Update other fields as needed...
        db.session.commit()
        flash('User information updated successfully.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_user.html', user=user,form=form)



#delete route............
# Base form with CSRF protection enabled
class MyBaseForm(FlaskForm):
    class Meta:
        csrf = True

# Form for deleting a user
class DeleteUserForm(MyBaseForm):
    submit = SubmitField('Delete')

@app.route('/delete_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    form = DeleteUserForm()
    if request.method == 'POST':
        # Proceed to delete the user if the method is POST
        try:
            db.session.delete(user)
            db.session.commit()
            flash('User deleted successfully.', 'success')
        except Exception as e:
            db.session.rollback() 
            flash(f'Error deleting user: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('confirm.html', user=user, form=form)


# #homepage route...........
@app.route("/", methods=['GET', 'POST'])
def home():
        
        return redirect(url_for('login'))
        # return render_template("login.html")
        

#The /register route handles user registration, hashing the password before storing it.

@app.route('/register', methods=['GET', 'POST'])
@csrf.exempt
def register():
    form = RegistrationForm(csrf_enabled=False)  # Disable CSRF for this form

    if form.validate_on_submit():
        try:
            business_name = form.business_name.data
            business_address = form.business_address.data
            phone_number = form.phone_number.data
            email = form.email.data
            state = form.state.data
            password = form.password.data
            confirm_password = generate_password_hash(password, method='pbkdf2:sha256')

            # Additional fields
            business_project = form.business_project.data
            value_chain_cat = form.value_chain_cat.data
            borrowing_relationship = form.borrowing_relationship.data
            fresh_loan_request = form.fresh_loan_request.data
            request_submitted_to_bank = form.request_submitted_to_bank.data
            feasibility_study_available = form.feasibility_study_available.data
            proposed_facility_amount = form.proposed_facility_amount.data
            purpose_of_facility = form.purpose_of_facility.data
            name_of_bank = form.name_of_bank.data
            security_proposed = form.security_proposed.data
            highlights_of_discussion = form.highlights_of_discussion.data
            rm_bm_name_phone_number = form.rm_bm_name_phone_number.data
            rm_bm_email = form.rm_bm_email.data
            status_update = form.status_update.data
            challenges = form.challenges.data
            proposed_next_steps = form.proposed_next_steps.data

            # Check for existing user
            if User.query.filter_by(email=email).first():
                flash('Email already registered!', 'danger')
                return redirect(url_for('register'))
            if User.query.filter_by(business_name=business_name).first():
                flash('Business Name already registered!', 'danger')
                return redirect(url_for('register'))

            # Create and save new user
            new_user = User(
                business_name=business_name,
                business_address=business_address,
                phone_number=phone_number,
                email=email,
                state=state,
                password=confirm_password,
                business_project=business_project,
                value_chain_cat=value_chain_cat,
                borrowing_relationship=borrowing_relationship,
                fresh_loan_request=fresh_loan_request,
                request_submitted_to_bank=request_submitted_to_bank,
                feasibility_study_available=feasibility_study_available,
                proposed_facility_amount=proposed_facility_amount,
                purpose_of_facility=purpose_of_facility,
                name_of_bank=name_of_bank,
                security_proposed=security_proposed,
                highlights_of_discussion=highlights_of_discussion,
                rm_bm_name_phone_number=rm_bm_name_phone_number,
                rm_bm_email=rm_bm_email,
                status_update=status_update,
                challenges=challenges,
                proposed_next_steps=proposed_next_steps
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('register'))

    # Render form with validation errors (if any)
    return render_template('register.html', form=form)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/login', methods=['GET', 'POST'])
@csrf.exempt
def login():

    form = LoginForm()
    if form.validate_on_submit():
        # Clear any existing session data
        session.clear()
        email = form.email.data
        password = form.password.data
        # Check for user login
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['email'] = user.email
            session['is_admin'] = False
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        
        # Check for admin login
        admin = Admin.query.filter_by(email=email).first()
        if admin and check_password_hash(admin.password, password):
            session['user_id'] = admin.id
            session['email'] = admin.email
            session['is_admin'] = True
            flash('Login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        
        # If login fails
        flash('Login failed. Check your credentials and try again.', 'danger')
    
    return render_template('login.html', form=form)


# #dashboard and function ..............
@app.route('/dashboard')
@login_required
def dashboard():

    form = DeleteUserForm()
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user, form=form)

#admin.............route

@app.route('/admin_dashboard', methods=['GET', 'POST'])
@admin_required
def admin_dashboard():
    form = PredictionForm()
    search_form = SearchForm()  # Assuming you have a SearchForm class for the search functionality
    
    # Handle search form submission
    if search_form.validate_on_submit():
        search_term = search_form.search_term.data
        user = User.query.filter((User.id == search_term) | (User.email == search_term)).first()
        if user:
            return render_template('admin_dashboard.html', form=form, search_form=search_form, user=user)
        else:
            flash('User not found', 'danger')
            return render_template('admin_dashboard.html', form=form, search_form=search_form)
    
    return render_template('admin_dashboard.html', form=form, search_form=search_form)


# Admin registration route
# Admin registration route
@app.route('/register_admin', methods=['GET', 'POST'])
# @admin_required
def register_admin():

    form = RegisterAdminForm()
    if form.validate_on_submit():
        admin_name = form.admin_name.data
        admin_address = form.admin_address.data
        phone_number = form.phone_number.data
        email = form.email.data
        password = form.password.data
        confirm_password = generate_password_hash(password)
        is_admin = True  # Ensure the new user is an admin

        # Check if user email already exists
        existing_admin = Admin.query.filter_by(email=email).first()
        if existing_admin:
            flash('Email already registered!', 'danger')
            return redirect(url_for('register_admin'))

        existing_admin = Admin.query.filter_by(admin_name=admin_name).first()
        if existing_admin:
            flash('Admin already registered!', 'danger')
            return redirect(url_for('register_admin'))

        # If no duplicates proceed...
        new_admin = Admin(
            admin_name=admin_name,
            admin_address=admin_address,
            phone_number=phone_number,
            email=email,
            password=confirm_password,
            is_admin=is_admin
        )

        db.session.add(new_admin)
        db.session.commit()

        flash('New admin registered successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('register_admin.html', form=form)

# #prediction route from login dashboard and function ..............
@app.route('/prediction')
@login_required
def prediction():
    user = User.query.get(session['user_id'])
    # csrf_token = generate_csrf()
    form = PredictionForm()
    return render_template('prediction.html', user=user, form=form)
    # return render_template('prediction.html')


# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))
    
#search.......#############....

@app.route('/search', methods=['GET', 'POST'])
@admin_required
def search():
    search_form = SearchForm()
    form = PredictionForm()
    if search_form.validate_on_submit():
        search_term = search_form.search_term.data
        user = User.query.filter((User.prediction_id == search_term) | (User.email == search_term)).first()
        if user:
            return render_template('admin_dashboard.html', form=form, search_form=search_form, user=user)
        else:
            flash('No user found with that ID or email.', 'danger')
            return redirect(url_for('admin_dashboard'))
    return render_template('admin_dashboard.html', form=form, search_form=search_form)



#predict route....
@app.route('/predict', methods=['POST', 'GET'])
@login_required
@csrf.exempt
def predict():

    form = PredictionForm(csrf_enabled=False)   # Create an instance of the PredictionForm class
    
    if form.validate_on_submit():

        # Fetch the form data
        business_project = form.BUSINESS_PROJECT.data
        value_chain_cat = form.VALUE_CHAIN_CATEGORY.data
        borrowing_relationship = form.BORROWING_RELATIONSHIP.data
        fresh_loan_request = form.FRESH_LOAN_REQUEST.data
        request_submitted_to_bank = form.REQUEST_SUBMITTED_TO_BANK.data
        feasibility_study_available = form.FEASIBILITY_STUDY_AVAILABLE.data
        proposed_facility_amount = form.PROPOSED_FACILITY_AMOUNT.data

        # Save form data to session
        session['form_data'] = {
            'business_project': business_project,
            'value_chain_cat': value_chain_cat,
            'borrowing_relationship': borrowing_relationship,
            'fresh_loan_request': fresh_loan_request,
            'request_submitted_to_bank': request_submitted_to_bank,
            'feasibility_study_available': feasibility_study_available,
            'proposed_facility_amount': proposed_facility_amount
        }

        # Dataframe for model
        df = pd.DataFrame({
            'BUSINESS_PROJECT': [business_project],
            'VALUE_CHAIN_CATEGORY': [value_chain_cat],
            'BORROWING_RELATIONSHIP': [borrowing_relationship],
            'FRESH_LOAN_REQUEST': [fresh_loan_request],
            'REQUEST_SUBMITTED_TO_BANK': [request_submitted_to_bank],
            'FEASIBILITY_STUDY_AVAILABLE': [feasibility_study_available],
            'PROPOSED_FACILITY_AMOUNT': [proposed_facility_amount]
        })
        encoder_dicts = {
            'BUSINESS_PROJECT': {'EXISTING': 0, 'NEW': 1},
            'VALUE_CHAIN_CATEGORY': {
                'MIDSTREAM': 0,
                'PRE-UPSTREAM': 1,
                'UPSTREAM': 2,
                'DOWNSTREAM': 3,
                'UPSTREAM AND MIDSTREAM': 4,
                'MIDSTREAM AND DOWNSTREAM': 5,
                'UPSTREAM AND DOWNSTREAM': 6
            },
            'BORROWING_RELATIONSHIP': {'YES': 0, 'NO': 1},
            'FRESH_LOAN_REQUEST': {'YES': 0, 'NO': 1},
            'REQUEST_SUBMITTED_TO_BANK': {'YES': 0, 'NO': 1},
            'FEASIBILITY_STUDY_AVAILABLE': {'YES': 0, 'NO': 1, 'NIL': 2}
        }

        for col, values in encoder_dicts.items():
            df[col].replace(values, inplace=True)

        loaded_model = joblib.load('../notebook/xgboost.joblib')
        prediction = loaded_model.predict(df)

        if prediction[0] == 1:
            user = User.query.get(session['user_id'])
            if user:
                prediction_id = user.prediction_id
                if prediction_id is None:
                    prediction_id = generate_unique_code()
                    user.prediction_id = prediction_id

                # Update existing user data
                user.business_project = business_project
                user.value_chain_cat = value_chain_cat
                user.borrowing_relationship = borrowing_relationship
                user.fresh_loan_request = fresh_loan_request
                user.request_submitted_to_bank = request_submitted_to_bank
                user.feasibility_study_available = feasibility_study_available
                user.proposed_facility_amount = proposed_facility_amount

                db.session.commit()
                flash(f"Your loan request is successful. Your prediction ID is {prediction_id}.")
                return render_template("approval.html", user=user, prediction_id=prediction_id, form=form)
            else:
                flash("User not found. Please log in again.")
                return redirect(url_for('login'))
        else:
            flash("Your loan request is denied.")
            user = User.query.get(session['user_id'])
            return render_template("disapproval.html", user=user, form=form)
        
    elif request.method == 'GET':
        if 'form_data' in session:
            form_data = session['form_data']
            form.BUSINESS_PROJECT.data = form_data['business_project']
            form.VALUE_CHAIN_CATEGORY.data = form_data['value_chain_cat']
            form.BORROWING_RELATIONSHIP.data = form_data['borrowing_relationship']
            form.FRESH_LOAN_REQUEST.data = form_data['fresh_loan_request']
            form.REQUEST_SUBMITTED_TO_BANK.data = form_data['request_submitted_to_bank']
            form.FEASIBILITY_STUDY_AVAILABLE.data = form_data['feasibility_study_available']
            form.PROPOSED_FACILITY_AMOUNT.data = form_data['proposed_facility_amount']

    return render_template("prediction.html", form=form)

#API register route 
@app.route('/api/register', methods=['POST'])
@csrf.exempt
def api_register():
    data = request.get_json()  # Parse JSON data from request
    
    if data:
        form = RegistrationForm(csrf_enabled=False)  # Disable CSRF for API use
        
        # Manually populate form fields with JSON data
        form.business_name.data = data.get('business_name')
        form.business_address.data = data.get('business_address')
        form.phone_number.data = data.get('phone_number')
        form.email.data = data.get('email')
        form.state.data = data.get('state')
        form.password.data = data.get('password')
        form.confirm_password.data = data.get('confirm_password')

        # Additional fields
        form.business_project.data = data.get('business_project')
        form.value_chain_cat.data = data.get('value_chain_cat')
        form.borrowing_relationship.data = data.get('borrowing_relationship')
        form.fresh_loan_request.data = data.get('fresh_loan_request')
        form.request_submitted_to_bank.data = data.get('request_submitted_to_bank')
        form.feasibility_study_available.data = data.get('feasibility_study_available')
        form.proposed_facility_amount.data = data.get('proposed_facility_amount')
        form.purpose_of_facility.data = data.get('purpose_of_facility')
        form.name_of_bank.data = data.get('name_of_bank')
        form.security_proposed.data = data.get('security_proposed')
        form.highlights_of_discussion.data = data.get('highlights_of_discussion')
        form.rm_bm_name_phone_number.data = data.get('rm_bm_name_phone_number')
        form.rm_bm_email.data = data.get('rm_bm_email')
        form.status_update.data = data.get('status_update')
        form.challenges.data = data.get('challenges')
        form.proposed_next_steps.data = data.get('proposed_next_steps')
        
        if form.validate():
            try:
                # Extract form data
                business_name = form.business_name.data
                business_address = form.business_address.data
                phone_number = form.phone_number.data
                email = form.email.data
                state = form.state.data
                password = form.password.data
                confirm_password = generate_password_hash(password, method='pbkdf2:sha256')

                # Additional fields
                business_project = form.business_project.data
                value_chain_cat = form.value_chain_cat.data
                borrowing_relationship = form.borrowing_relationship.data
                fresh_loan_request = form.fresh_loan_request.data
                request_submitted_to_bank = form.request_submitted_to_bank.data
                feasibility_study_available = form.feasibility_study_available.data
                proposed_facility_amount = form.proposed_facility_amount.data
                purpose_of_facility = form.purpose_of_facility.data
                name_of_bank = form.name_of_bank.data
                security_proposed = form.security_proposed.data
                highlights_of_discussion = form.highlights_of_discussion.data
                rm_bm_name_phone_number = form.rm_bm_name_phone_number.data
                rm_bm_email = form.rm_bm_email.data
                status_update = form.status_update.data
                challenges = form.challenges.data
                proposed_next_steps = form.proposed_next_steps.data

                # Check for existing user
                if User.query.filter_by(email=email).first():
                    return jsonify({"error": "Email already registered!"}), 400
                if User.query.filter_by(business_name=business_name).first():
                    return jsonify({"error": "Business Name already registered!"}), 400

                # Create and save new user
                new_user = User(
                    business_name=business_name,
                    business_address=business_address,
                    phone_number=phone_number,
                    email=email,
                    state=state,
                    password=confirm_password,
                    business_project=business_project,
                    value_chain_cat=value_chain_cat,
                    borrowing_relationship=borrowing_relationship,
                    fresh_loan_request=fresh_loan_request,
                    request_submitted_to_bank=request_submitted_to_bank,
                    feasibility_study_available=feasibility_study_available,
                    proposed_facility_amount=proposed_facility_amount,
                    purpose_of_facility=purpose_of_facility,
                    name_of_bank=name_of_bank,
                    security_proposed=security_proposed,
                    highlights_of_discussion=highlights_of_discussion,
                    rm_bm_name_phone_number=rm_bm_name_phone_number,
                    rm_bm_email=rm_bm_email,
                    status_update=status_update,
                    challenges=challenges,
                    proposed_next_steps=proposed_next_steps
                )
                db.session.add(new_user)
                db.session.commit()
                return jsonify({"message": "Registration successful!"}), 201

            except Exception as e:
                return jsonify({"error": str(e)}), 500
        else:
            return jsonify({"errors": form.errors}), 400
    else:
        return jsonify({"error": "Invalid JSON data"}), 400
    
   
# Login using API
@app.route('/api/login', methods=['POST'])
@csrf.exempt
def api_login():
    try:
        # Get JSON data from request
        data = request.json

        # Convert JSON data to a MultiDict
        form_data = MultiDict(data)
        form = LoginForm(form_data, csrf_enabled=False)  # Disable CSRF for the form

        # Validate form data
        if form.validate():
            # Clear any existing session data
            session.clear()
            email = form.email.data
            password = form.password.data

            # Check for user login
            user = User.query.filter_by(email=email).first()
            if user and check_password_hash(user.password, password):
                session['user_id'] = user.id
                session['email'] = user.email
                session['is_admin'] = False
                return jsonify({
                    'message': 'Login successful!',
                    'user_id': user.id,
                    'email': user.email,
                    'is_admin': False
                }), 200

            # Check for admin login
            admin = Admin.query.filter_by(email=email).first()
            if admin and check_password_hash(admin.password, password):
                session['user_id'] = admin.id
                session['email'] = admin.email
                session['is_admin'] = True
                return jsonify({
                    'message': 'Login successful!',
                    'user_id': admin.id,
                    'email': admin.email,
                    'is_admin': True
                }), 200

            # If login fails
            return jsonify({'error': 'Login failed. Check your credentials and try again.'}), 401

        else:
            # Return form validation errors
            return jsonify({'errors': form.errors}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500



#api for  predict 
# Ensure to set this to the correct path on your server
# Define the absolute path to the model
MODEL_PATH = os.path.join(os.path.dirname(__file__), '../notebook/xgboost.joblib')
@app.route('/api/predict', methods=['POST'])
@csrf.exempt
def api_predict():
    try:
        # Get JSON data from request
        data = request.json

        # Convert JSON data to a MultiDict
        form_data = MultiDict(data)
        form = PredictionForm(form_data, csrf_enabled=False)  # Disable CSRF for the form

        # Validate form data
        if form.validate_on_submit():
            # Fetch the form data
            business_project = form.BUSINESS_PROJECT.data
            value_chain_cat = form.VALUE_CHAIN_CATEGORY.data
            borrowing_relationship = form.BORROWING_RELATIONSHIP.data
            fresh_loan_request = form.FRESH_LOAN_REQUEST.data
            request_submitted_to_bank = form.REQUEST_SUBMITTED_TO_BANK.data
            feasibility_study_available = form.FEASIBILITY_STUDY_AVAILABLE.data
            proposed_facility_amount = form.PROPOSED_FACILITY_AMOUNT.data

            # Dataframe for model
            df = pd.DataFrame({
                'BUSINESS_PROJECT': [business_project],
                'VALUE_CHAIN_CATEGORY': [value_chain_cat],
                'BORROWING_RELATIONSHIP': [borrowing_relationship],
                'FRESH_LOAN_REQUEST': [fresh_loan_request],
                'REQUEST_SUBMITTED_TO_BANK': [request_submitted_to_bank],
                'FEASIBILITY_STUDY_AVAILABLE': [feasibility_study_available],
                'PROPOSED_FACILITY_AMOUNT': [proposed_facility_amount]
            })

            encoder_dicts = {
                'BUSINESS_PROJECT': {'EXISTING': 0, 'NEW': 1},
                'VALUE_CHAIN_CATEGORY': {
                    'MIDSTREAM': 0,
                    'PRE-UPSTREAM': 1,
                    'UPSTREAM': 2,
                    'DOWNSTREAM': 3,
                    'UPSTREAM AND MIDSTREAM': 4,
                    'MIDSTREAM AND DOWNSTREAM': 5,
                    'UPSTREAM AND DOWNSTREAM': 6
                },
                'BORROWING_RELATIONSHIP': {'YES': 0, 'NO': 1},
                'FRESH_LOAN_REQUEST': {'YES': 0, 'NO': 1},
                'REQUEST_SUBMITTED_TO_BANK': {'YES': 0, 'NO': 1},
                'FEASIBILITY_STUDY_AVAILABLE': {'YES': 0, 'NO': 1, 'NIL': 2}
            }

            for col, values in encoder_dicts.items():
                df[col].replace(values, inplace=True)

            # Ensure the correct path for the model
            MODEL_PATH = '/home/hoghidan1/NRS/NR/notebook/xgboost.joblib'
            loaded_model = joblib.load(MODEL_PATH)
            prediction = loaded_model.predict(df)

            # Assuming that session['user_id'] is not necessary for an API, removing session dependency.
            # You might need to replace it with another form of user identification if needed.
            # For instance, JWT token verification can be used to get user information.

            if prediction[0] == 1:
                return jsonify({
                    'message': "Your loan request is successful.",
                    'prediction_id': generate_unique_code()  # Generate a unique ID for prediction
                }), 200
            else:
                return jsonify({'message': "Your loan request is denied."}), 200

        else:
            return jsonify({'errors': form.errors}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500




#users route 
@app.route('/users')
@admin_required
def show_users():
    users = User.query.all()
    return render_template('users.html', users=users)


#show all admins in table route 
@app.route('/admins')
@admin_required
def show_admins():
    admins = Admin.query.all()
    return render_template('admins.html', admins=admins)
   
if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)


