from flask import current_app
from flask_sqlalchemy import SQLAlchemy

# Assuming you have the User model already defined

db = SQLAlchemy()

def create_admin_user():
    admin_user = User(
        email='admin@example.com',
        password='hashed_password',  # You should hash the password
        full_name='Admin User',
        phone_number='1234567890',
        is_verified=True,
        is_admin=True,
        role='admin'
    )
    db.session.add(admin_user)
    db.session.commit()
    print('Admin user created successfully')

if __name__ == '__main__':
    with current_app.app_context():
        create_admin_user()
