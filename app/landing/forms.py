from flask_wtf import FlaskForm
from wtforms import SubmitField, FloatField, StringField, IntegerField, SelectField, PasswordField, Regexp
from wtforms.validators import ValidationError, DataRequired, Length, Email, EqualTo, Optional

#local imports
from .form_variables import state_options
from app.models import User


class RegistrationForm(FlaskForm):
    business_name = StringField('Business Name', validators=[DataRequired(), Length(min=10, max=100)])
    business_address = StringField('Business Address', validators=[DataRequired(), Length(min=10, max=100)])
    phone_number = StringField('Phone Number', validators=[DataRequired(), Length(max=15), Regexp(regex='^\d+$', message="Phone number must contain only digits")])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=100)])
    state = SelectField('State', choices=state_options, validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])

    #optional fields
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

    # Check for existing user
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data.lower()).first()
        if user:
            raise ValidationError('Email already registered!')
        
    # Check for business name
    def validate_business_name(self, business_name):
        biz_entity = User.query.filter_by(business_name=business_name.data).first()
        if biz_entity:
            raise ValidationError('Business Name already registered!')




