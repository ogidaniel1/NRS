from flask import Flask, render_template, request, redirect, url_for, flash,jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_required, login_user, logout_user, UserMixin, current_user
from Crypto.Hash import SHA256
from flask_migrate import Migrate
from alembic import op
import sqlalchemy as sa
from functools import wraps

#pip install pycryptodome
# from pycryptodome.Hash import *




import pandas as pd
import joblib
import pickle, sqlite3
import uuid, random, string


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
 

  


#10 digit codes for the prediction aprroval page

def generate_unique_code():
    return ''.join(random.choices('0123456789', k=10))


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
        new_user = User(business_name=business_name, business_address=business_address, phone_number=phone_number, email=email, state=state, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


#wrapper..................
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You need to be logged in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['email'] = user.email
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))  # Redirect to the dashboard page
        else:
            flash('Login failed. Check your credentials and try again.', 'danger')
    
    return render_template('login.html')

# #dashboard and function ..............

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)


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
def search():
    if request.method == 'POST':
        
        search_term = request.form.get('search_term')
        user = User.query.filter((User.id == search_term) | (User.email == search_term)).first()
        if user:
            return render_template('search_results.html', user=user)
        else:
            flash('No user found with that ID or email.', 'danger')
            return redirect(url_for('dashboard'))
    return render_template('search.html') 


#prediction function...................
@app.route('/predict', methods=['POST', 'GET'])
def predict():
    if request.method == 'POST':
        business_project = request.form.get('BUSINESS_PROJECT')
        value_chain_cat = request.form.get('VALUE_CHAIN_CATEGORY')
        borrrowing_relationship = request.form.get('BORROWING_RELATIONSHIP')
        fresh_loan_request = request.form.get('FRESH_LOAN_REQUEST')
        request_submitted_to_bank = request.form.get('REQUEST_SUBMITTED_TO_BANK')
        feasibility_study_available = request.form.get('FEASIBILITY_STUDY_AVAILABLE')
        proposed_facility_amount = float(request.form.get('PROPOSED_FACILITY_AMOUNT'))

        df = pd.DataFrame({
            'BUSINESS_PROJECT': [business_project],
            'VALUE_CHAIN_CATEGORY': [value_chain_cat],
            'BORROWING_RELATIONSHIP': [borrrowing_relationship],
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
            prediction_id = str(uuid.uuid4())
            if 'user_id' in session:
                user = User.query.get(session['user_id'])
                user.prediction_id = prediction_id
                db.session.commit()
            flash(f"Your loan request has been granted. Your prediction ID is {prediction_id}.")
            return render_template("approval.html", prediction_id=prediction_id)
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
        borrrowing_relationship = request.json.get('BORROWING_RELATIONSHIP')
        fresh_loan_request = request.json.get('FRESH_LOAN_REQUEST')
        request_submitted_to_bank = request.json.get('REQUEST_SUBMITTED_TO_BANK')
        feasibility_study_available = request.json.get('FEASIBILITY_STUDY_AVAILABLE')
        proposed_facility_amount = float(request.json.get('PROPOSED_FACILITY_AMOUNT'))

        df = pd.DataFrame(
        {'BUSINESS_PROJECT': [business_project],
         'VALUE_CHAIN_CATEGORY': [value_chain_cat],
         'BORROWING_RELATIONSHIP': [borrrowing_relationship],
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
   
if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
