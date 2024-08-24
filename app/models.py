from flask_login import UserMixin

#local imports
from app import db, login_manager


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):

    id = db.Column(db.Integer, primary_key=True)
    business_name = db.Column(db.String(150), nullable=False)
    business_address = db.Column(db.String(150), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    state = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)

    #optional fields
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


class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    admin_name = db.Column(db.String(150), nullable=False)
    admin_address = db.Column(db.String(150), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)




