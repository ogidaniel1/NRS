from flask import Flask, render_template, request, redirect, url_for, flash,jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Hash import SHA256

#pip install pycryptodome
# from pycryptodome.Hash import *

import pandas as pd
import joblib
import pickle, sqlite3


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

#The User class defines the database model.

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    business_name = db.Column(db.String(150), nullable=False)
    business_address = db.Column(db.String(150), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    state = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)


# #homepage route...........
@app.route("/")
def home():
        # return render_template("login.html")
        return render_template("index.html")
    


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


#login route and function ..............
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
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your credentials and try again.', 'danger')
    
    return render_template('login.html')
    
# Logout route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

#dashboard of users................

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        # Retrieve user information if needed
        user = User.query.get(session['user_id'])
        return render_template('dashboard.html', user=user)
    else:
        flash('You need to log in first.', 'warning')
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
    """Function that predicts whether or not a user is qualified for a loan"""
    if request.method == 'POST':

        # Receiving user inputs
        business_project = request.form.get('BUSINESS_PROJECT') 
        value_chain_cat = request.form.get('VALUE_CHAIN_CATEGORY')
        borrrowing_relationship = request.form.get('BORROWING_RELATIONSHIP')
        fresh_loan_request = request.form.get('FRESH_LOAN_REQUEST')
        request_submitted_to_bank = request.form.get('REQUEST_SUBMITTED_TO_BANK')
        feasibility_study_available = request.form.get('FEASIBILITY_STUDY_AVAILABLE')
        proposed_facility_amount = float(request.form.get('PROPOSED_FACILITY_AMOUNT'))


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
            flash("your loan request has been granted")
            return render_template("approval.html")
        else:
            flash("your loan request is denied")
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
