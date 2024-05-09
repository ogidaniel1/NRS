from flask import Flask, render_template, request
import pickle, sqlite3


app = Flask(__name__)

#declaring load model from ml codebase...pickle file
cv = pickle.load(open("../notebook/catboost_model.pkl", 'rb'))

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
   
        feature_list = [
            'name_of_entity','nature_of_business','business_project','contact_name_phone_email_of_promoter',
            'proposed_facility_amount','purpose_of_facility','value_chain_category','borrowing_relationship',
            'fresh_loan_request','request_submitted_to_bank','security_proposed','feasibility_study_available','state'
            ]
    
        features = [request.form[field] for field in feature_list] #getting values from the html form
        prediction = cv.predict(*features)
        prediction = 1 if prediction == 1 else -1
        return render_template("index.html", prediction = prediction) 
    return render_template("index.html") 

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
