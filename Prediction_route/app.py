from flask import Flask, request, jsonify
import pandas as pd
import joblib

app = Flask(__name__)

@app.route('/predict', methods=['POST'], strict_slashes=False)
def prediction_view():
    """Function that predicts whether or not a user is qualified for a loan"""
    
    # Receiving user inputs
    business_project = request.json.get('BUSINESS_PROJECT')
    value_chain_cat = request.json.get('VALUE_CHAIN_CATEGORY')
    borrrowing_relationship = request.json.get('BORROWING_RELATIONSHIP')
    fresh_loan_request = request.json.get('FRESH_LOAN_REQUEST')
    request_submitted_to_bank = request.json.get('REQUEST_SUBMITTED_TO_BANK')
    feasibility_study_available = request.json.get('FEASIBILITY_STUDY_AVAILABLE')
    proposed_facility_amount = request.json.get('PROPOSED_FACILITY_AMOUNT')

    df = pd.DataFrame(
        {'business_project': [business_project],
         'value_chain_cat': [value_chain_cat],
         'borrrowing_relationship': [borrrowing_relationship],
         'fresh_loan_request': [fresh_loan_request],
         'request_submitted_to_bank': [request_submitted_to_bank],
         'feasibility_study_available': [feasibility_study_available],
         'proposed_facility_amount': [proposed_facility_amount]
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
    loaded_model = joblib.load('xgboost.joblib')
    prediction = loaded_model.predict(df)

    if prediction[0] == 1:
        return jsonify({'granted': 'your loan request has been granted'})
    else:
        return jsonify({'denied': 'your loan request is denied'})

if __name__ == '__main__':
    app.run(debug=True)
