
from flask import Flask, render_template,flash, session, request
from datetime import timedelta
from flask_sqlalchemy  import SQLAlchemy
import numpy as np

import pickle, sqlite3


app = Flask(__name__)
app.secret_key = "hello"

#declaring load model from ml codebase...pickle file
cv = pickle.load(open("../notebook/xgboost.joblib", 'rb'))

@app.route("/")
#homepage route...........
def home():
    #request from the user page............
    flash("hello")
    return render_template("index.html")
    

@app.route("/predict", methods=['GET', 'POST'])       
def predict():

    if request.method == 'POST':
        # print()
    #all the list of features collected on the form as alist
        
        feature_list = [{
            'BUSINESS_PROJECT':1, 'VALUE_CHAIN_CATEGORY':2,
                          'BORROWING_RELATIONSHIP':1, 'FRESH_LOAN_REQUEST':1,
                          'REQUEST_SUBMITTED_TO_BANK':1, 'FEASIBILITY_STUDY_AVAILABLE':0, 'PROPOSED_FACILITY_AMOUNT':2000000000
            }]
        
        features = [request.form[field] for field in feature_list] #getting input values from the html form
        feature= np.array[[features]]
        print(feature)
        prediction = cv.predict(feature)
        prediction = 1 if prediction == 1 else -1
         
        return render_template("index.html", prediction = prediction) 
    # return render_template("index2.html") 

# @app.route("/api/predict", methods=[ 'POST'])

# def api_predict():

# #     features = request.form.get_json(force=True)
# #     prediction = cv.predict(*features)
# #     prediction = 1 if prediction == 1 else -1
#     return jsonify(prediction: prediction)
   

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
