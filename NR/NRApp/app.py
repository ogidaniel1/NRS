
from flask import Flask, render_template,flash, session, request
from datetime import timedelta
from flask_sqlalchemy  import SQLAlchemy
import numpy as np
import pandas as pd

import pickle, sqlite3


app = Flask(__name__)
app.secret_key = "hello"

#declaring load model from ml codebase...pickle file
cv = pickle.load(open("../notebook/xgboost.joblib", 'rb'))

@app.route("/")
#homepage route...........
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
