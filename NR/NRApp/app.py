from flask import Flask, render_template, request, redirect, url_for, flash,jsonify, abort,session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin,login_manager,current_user
from Crypto.Hash import SHA256
from flask_migrate import Migrate
from alembic import op
import sqlalchemy as sa
from functools import wraps
# from app import User, Admin  # Ensure these are imported from your app

#pip install pycryptodome
# from pycryptodome.Hash import *




import pandas as pd
import joblib
import pickle, sqlite3
import uuid, random, string,time
from datetime import timedelta


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

 

#10 digit codes for the prediction aprroval page

def generate_unique_code():
    return random.randint(1000000000, 9999999999)


#logged out session................
@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=5)
    session.modified = True
    session['last_activity'] = time.time()

@app.route('/check_activity', methods=['POST'])
def check_activity():
    if 'last_activity' in session:
        last_activity = session['last_activity']
        current_time = time.time()
        if current_time - last_activity > 300:
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



@app.route('/approve/<int:user_id>', methods=['GET', 'POST'])
@login_required
def approve(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.prediction_id = generate_unique_code()
        db.session.commit()
        flash(f'User {user.email} has been approved with Prediction ID {user.prediction_id}.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('approval.html', user=user)
     

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

    PURPOSE_OF_FACILITY = db.Column(db.String(100), nullable=True)
    NAME_OF_BANK = db.Column(db.String(100), nullable=True)
    SECURITY_PROPOSED = db.Column(db.String(100), nullable=True)
    HIGHLIGHTS_OF_DISCUSSION = db.Column(db.Text)
    RM_BM_NAME_PHONE_NUMBER = db.Column(db.String(100), nullable=True)
    RM_BM_EMAIL = db.Column(db.String(100), nullable=True)
    STATUS_UPDATE = db.Column(db.Text)
    CHALLENGES = db.Column(db.Text)
    PROPOSED_NEXT_STEPS = db.Column(db.Text)



class Admin(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    admin_name = db.Column(db.String(150), nullable=False)
    admin_address = db.Column(db.String(150), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)



@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Check if current user is admin
    if not session['is_admin']:
        abort(403)  # Forbidden
        
    
    if request.method == 'POST':
        # Update user information by admin officer
        user.PURPOSE_OF_FACILITY = request.form.get('purpose_of_facility') or None
        user.NAME_OF_BANK = request.form.get('name_of_bank') or None
        user.SECURITY_PROPOSED = request.form.get('security_proposed') or None
        user.HIGHLIGHTS_OF_DISCUSSION = request.form.get('highlights_of_discussion') or None
        user.RM_BM_NAME_PHONE_NUMBER = request.form.get('rm_bm_name_phone_number') or None
        user.RM_BM_EMAIL = request.form.get('rm_bm_email') or None
        user.STATUS_UPDATE = request.form.get('status_update') or None
        user.CHALLENGES = request.form.get('challenges') or None
        user.PROPOSED_NEXT_STEPS = request.form.get('proposed_next_steps') or None

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
        user.proposed_facility_amount = request.form.get('proposed_facility_amount') or 0
        if user.proposed_facility_amount:
            try:
                user.proposed_facility_amount = float(user.proposed_facility_amount)
            except ValueError:
                flash('Proposed facility amount must be a number.', 'danger')
                return render_template('edit_user.html', user=user)
        
        # Update other fields as needed...
        db.session.commit()
        flash('User information updated successfully.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_user.html', user=user)


# #homepage route...........
@app.route("/", methods=['GET', 'POST'])

def home():
                
        return render_template("login.html")
        

#The /register route handles user registration, hashing the password before storing it.

        
@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':
        business_name = request.form.get('business_name')
        business_address = request.form.get('business_address')
        phone_number = request.form.get('phone_number')
        email = request.form.get('email')
        state = request.form.get('state')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Add additional fields
        business_project = request.form.get('business_project')  # Ensure this field is populated
        value_chain_cat = request.form.get('value_chain_cat')
        borrowing_relationship = request.form.get('borrowing_relationship')
        fresh_loan_request = request.form.get('fresh_loan_request')
        request_submitted_to_bank = request.form.get('request_submitted_to_bank')
        feasibility_study_available = request.form.get('feasibility_study_available')
        proposed_facility_amount = request.form.get('proposed_facility_amount')
        purpose_of_facility = request.form.get('PURPOSE_OF_FACILITY')
        name_of_bank = request.form.get('NAME_OF_BANK')
        security_proposed = request.form.get('SECURITY_PROPOSED')
        highlights_of_discussion = request.form.get('HIGHLIGHTS_OF_DISCUSSION')
        rm_bm_name_phone_number = request.form.get('RM_BM_NAME_PHONE_NUMBER')
        rm_bm_email = request.form.get('RM_BM_EMAIL')
        status_update = request.form.get('STATUS_UPDATE')
        challenges = request.form.get('CHALLENGES')
        proposed_next_steps = request.form.get('PROPOSED_NEXT_STEPS')

        new_user = User(
            business_name=business_name,
            business_address=business_address,
            phone_number=phone_number,
            email=email,
            state=state,
            password=hashed_password,
            business_project=business_project,
            value_chain_cat=value_chain_cat,
            borrowing_relationship=borrowing_relationship,
            fresh_loan_request=fresh_loan_request,
            request_submitted_to_bank=request_submitted_to_bank,
            feasibility_study_available=feasibility_study_available,
            proposed_facility_amount=proposed_facility_amount,
            PURPOSE_OF_FACILITY=purpose_of_facility,
            NAME_OF_BANK=name_of_bank,
            SECURITY_PROPOSED=security_proposed,
            HIGHLIGHTS_OF_DISCUSSION=highlights_of_discussion,
            RM_BM_NAME_PHONE_NUMBER=rm_bm_name_phone_number,
            RM_BM_EMAIL=rm_bm_email,
            STATUS_UPDATE=status_update,
            CHALLENGES=challenges,
            PROPOSED_NEXT_STEPS=proposed_next_steps
        )

        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
#there is need to handle if user is already registered
    return render_template('register.html')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#login logic ..............
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Clear any existing session data
        session.clear()
        
        email = request.form.get('email')
        password = request.form.get('password')
        
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
    
    return render_template('login.html')



# #dashboard and function ..............

@app.route('/dashboard')
@login_required

def dashboard():
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)

#admin.............route

@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    
    return render_template('admin_dashboard.html')

# Admin registration route
@app.route('/register_admin', methods=['GET', 'POST'])
@admin_required
def register_admin():
    if request.method == 'POST':
        admin_name = request.form.get('admin_name')
        admin_address = request.form.get('admin_address')
        phone_number = request.form.get('phone_number')
        email = request.form.get('email')
        password = request.form.get('password')
        password_hash = generate_password_hash(password)
        is_admin = True  # Ensure the new user is an admin

        new_admin = Admin(
            admin_name=admin_name,
            admin_address=admin_address,
            phone_number=phone_number,
            email=email,
            password=password_hash,
            is_admin=is_admin
        )

        db.session.add(new_admin)
        db.session.commit()
        
        flash('New admin registered successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('register_admin.html')


# #prediction route from login dashboard and function ..............
@app.route('/prediction')
@login_required
def prediction():
    user = User.query.get(session['user_id'])
    return render_template('prediction.html', user=user)
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
    if request.method == 'POST':
        
        search_term = request.form.get('search_term')
        user = User.query.filter((User.id == search_term) | (User.email == search_term)).first()
        if user:
            return render_template('search.html', user=user)
        else:
            flash('No user found with that ID or email.', 'danger')
            return redirect(url_for('admin_dashboard'))
    return render_template('search.html') 


#prediction function...................
@app.route('/predict', methods=['POST', 'GET'])
def predict():
    if request.method == 'POST':
        business_project = request.form.get('BUSINESS_PROJECT')
        value_chain_cat = request.form.get('VALUE_CHAIN_CATEGORY')
        borrowing_relationship = request.form.get('BORROWING_RELATIONSHIP')
        fresh_loan_request = request.form.get('FRESH_LOAN_REQUEST')
        request_submitted_to_bank = request.form.get('REQUEST_SUBMITTED_TO_BANK')
        feasibility_study_available = request.form.get('FEASIBILITY_STUDY_AVAILABLE')
        proposed_facility_amount = float(request.form.get('PROPOSED_FACILITY_AMOUNT'))

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
                'MIDSTREAM': 0, 'PRE-UPSTREAM': 1, 'UPSTREAM': 2, 'DOWNSTREAM': 3,
                'UPSTREAM AND MIDSTREAM': 4, 'MIDSTREAM AND DOWNSTREAM': 5,
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
            if 'user_id' in session:
                user = User.query.get(session['user_id'])
                prediction_id = user.prediction_id
                if prediction_id is None:
                    prediction_id = generate_unique_code()
                    user.prediction_id = prediction_id
                    db.session.commit()
                flash(f"Your loan request has been granted. Your prediction ID is {prediction_id}.")
                return render_template("approval.html", prediction_id=prediction_id, user=user)
            else:
                flash("User not logged in.")
                return render_template("login.html")  # Redirect user to login page
        else:
            flash("Your loan request is denied.")
            return render_template("disapproval.html")


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password, password):
        session['user_id'] = user.id
        session['email'] = user.email
        return jsonify({'message': 'Login successful!'}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/api/dashboard', methods=['GET'])
def api_dashboard():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return jsonify({'email': user.email, 'user_id': user.id}), 200
    else:
        return jsonify({'message': 'You need to log in first.'}), 403

   
@app.route("/api/predict", methods=['POST'], strict_slashes=False)

def api_predict():

        """Function that predicts whether or not a user is qualified for a loan"""
    
        # Receiving user inputs
        business_project = request.json.get('BUSINESS_PROJECT')
        value_chain_cat = request.json.get('VALUE_CHAIN_CATEGORY')
        borrowing_relationship = request.json.get('BORROWING_RELATIONSHIP')
        fresh_loan_request = request.json.get('FRESH_LOAN_REQUEST')
        request_submitted_to_bank = request.json.get('REQUEST_SUBMITTED_TO_BANK')
        feasibility_study_available = request.json.get('FEASIBILITY_STUDY_AVAILABLE')
        proposed_facility_amount = float(request.json.get('PROPOSED_FACILITY_AMOUNT'))

        df = pd.DataFrame(
        {'BUSINESS_PROJECT': [business_project],
         'VALUE_CHAIN_CATEGORY': [value_chain_cat],
         'BORROWING_RELATIONSHIP': [borrowing_relationship],
         'FRESH_LOAN_REQUEST': [fresh_loan_request],
         'REQUEST_SUBMITTED_TO_BANK': [request_submitted_to_bank],
         'FEASIBILITY_STUDY_AVAILABLE': [feasibility_study_available],
         'PROPOSED_FACILITY_AMOUNT': [proposed_facility_amount]
        }
        )
        # print(df)
        # Encoding dicts
        encoder_dicts = {
            'BUSINESS_PROJECT': {'EXISTING': 0, 'NEW': 1}, 
            'VALUE_CHAIN_CATEGORY': {'MIDSTREAM': 0, 'PRE-UPSTREAM': 1, 'UPSTREAM': 2, 'DOWNSTREAM': 3, \
                                    'UPSTREAM AND MIDSTREAM': 4, 'MIDSTREAM AND DOWNSTREAM': 5, \
                                    'UPSTREAM AND DOWNSTREAM': 6},
            'BORROWING_RELATIONSHIP': {'YES': 0, 'NO': 1},
            'FRESH_LOAN_REQUEST': {'YES': 0, 'NO': 1}, 
            'REQUEST_SUBMITTED_TO_BANK': {'YES': 0, 'NO': 1},
            'FEASIBILITY_STUDY_AVAILABLE': {'YES': 0, 'NO': 1, 'NIL': 2}
        }

        for col, values in encoder_dicts.items():
            df[col].replace(values, inplace=True)

        # Load the model
        loaded_model = joblib.load('../notebook/xgboost.joblib')
        prediction = loaded_model.predict(df)

        if prediction[0] == 1:
            return jsonify({'granted': 'your loan request has been granted'})
        else:
            return jsonify({'denied': 'your loan request is denied'})


#users route 
@app.route('/users')
def show_users():
    users = User.query.all()
    return render_template('users.html', users=users)


#show all admins in table route 
@app.route('/admins')
def show_admins():
    admins = Admin.query.all()
    return render_template('admins.html', admins=admins)
   
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Database initialized!")
    app.run(host='0.0.0.0', debug=True)
