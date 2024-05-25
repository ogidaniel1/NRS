
from flask import Flask, render_template, request, session, redirect, url_for, flash
from datetime import timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy  import SQLAlchemy
import numpy as np
import pandas as pd




import pickle, sqlite3


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)


#declaring load model from ml codebase...pickle file
cv = pickle.load(open("../notebook/catboost.joblib", 'rb'))

#The User class defines the database model.

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    business_name = db.Column(db.String(150), nullable=False)
    business_address = db.Column(db.String(150), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    state = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)

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
        
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(business_name=business_name, business_address=business_address, phone_number=phone_number, email=email, state=state, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

#The /login route handles user login, checking the hashed password.

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your credentials and try again.', 'danger')
    return render_template('login.html')

#The /dashboard route is a placeholder for the user's dashboard after a successful login.

@app.route('/dashboard')
def dashboard():
    
    return 'Welcome to your dashboard for prediction'
    # return render_template("index.html")

#homepage route...........
@app.route("/")
def home():
    #request from the user page............
    
    return render_template("index.html")
    
@app.route("/predict", methods=['GET', 'POST'])       
def predict():

    if request.method == 'POST':
        # print()
    #all the list of features collected on the form as alist
    #receiving values from frontend page 

        features = [
        request.form.get('BUSINESS_PROJECT'),
        request.form.get('VALUE_CHAIN_CATEGORY'),
        request.form.get('BORROWING_RELATIONSHIP'),
        request.form.get('FRESH_LOAN_REQUEST'),
        request.form.get('REQUEST_SUBMITTED_TO_BANK'),
        request.form.get('FEASIBILITY_STUDY_AVAILABLE'),
        request.form.get('PROPOSED_FACILITY_AMOUNT')
       ]

        #encoding features
        encoded_features = [pd.get_dummies(feature) for feature in features]
        
        data = pd.concat(encoded_features, axis = 1)
        # print(data)
        # make prediction withtrained model 
        prediction = cv.predict(data)
        prediction = 1 if prediction == 1 else -1     
        return render_template("index.html") 
    

# @app.route("/api/predict", methods=['POST'])

# def api_predict():

# #     features = request.form.get_json(force=True)
# #     prediction = cv.predict(*features)
# #     prediction = 1 if prediction == 1 else -1
#     return jsonify(prediction: prediction)
   

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
