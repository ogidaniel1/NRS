from flask import Blueprint, render_template, redirect, url_for, flash, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user

#local imports
from .forms import RegistrationForm, LoginForm
from app.models import User, Admin
from app import db

landing = Blueprint('landing', __name__)

@landing.route("/")
def home():
    return redirect(url_for('landing.login'))


@landing.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        try:
            # Create and save new user
            new_user = User(
                business_name=form.business_name.data,
                business_address=form.business_address.data,
                phone_number=form.phone_number.data,
                email=form.email.data.lower(),
                state=form.state.data,
                password=generate_password_hash(form.confirm_password, method='pbkdf2:sha256'),
                business_project=form.business_project.data,
                value_chain_cat=form.value_chain_cat.data,
                borrowing_relationship=form.borrowing_relationship.data,
                fresh_loan_request=form.fresh_loan_request.data,
                request_submitted_to_bank=form.request_submitted_to_bank.data,
                feasibility_study_available=form.feasibility_study_available.data,
                proposed_facility_amount=form.proposed_facility_amount.data,
                purpose_of_facility=form.purpose_of_facility.data,
                name_of_bank=form.name_of_bank.data,
                security_proposed=form.security_proposed.data,
                highlights_of_discussion=form.highlights_of_discussion.data,
                rm_bm_name_phone_number=form.rm_bm_name_phone_number.data,
                rm_bm_email=form.rm_bm_email.data,
                status_update=form.status_update.data,
                challenges=form.challenges.data,
                proposed_next_steps=form.proposed_next_steps.data
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('landing.login'))
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')

    page_vars = {'page_name': 'New Registration', 'form':form}
    return render_template('landing/register.html', page_vars=page_vars)


@landing.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page) if next_page \
                else redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your credentials and try again.', 'danger')
        
    page_vars = {'page_name': 'Login', 'form':form}
    return render_template('landing/login.html', page_vars=page_vars)
        
@landing.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    form = LoginForm()

    if form.validate_on_submit():
        # Check for admin login
        admin = Admin.query.filter_by(email=form.email.data.lower()).first()
        if admin and check_password_hash(admin.password, form.password.data):
            login_user(admin, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page) if next_page \
                else redirect(url_for('admin_dashboard'))
        
        else:
            flash('Login failed. Check your credentials and try again.', 'danger')
    
    page_vars = {'page_name': 'Admin Login', 'form':form}
    return render_template('landing/login.html', page_vars=page_vars)



