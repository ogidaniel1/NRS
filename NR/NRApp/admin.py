from app import db, User
from werkzeug.security import generate_password_hash
from functools import wraps
from flask import session, redirect, url_for, flash


admin_user = User(
    business_name="Admin Business",
    business_address="Admin Address",
    phone_number="1234567890",
    email="admin@nrs.com",
    state="Admin State",
    # password=generate_password_hash("adminpassword", method='sha256'),
    password = generate_password_hash("password", method='pbkdf2:sha256'),
    is_admin=True
)

db.session.add(admin_user)
db.session.commit()






 