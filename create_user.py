from app import app, db, User
from werkzeug.security import generate_password_hash

username = 'admin'
password = 'admin123'

hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

new_user = User(username=username, password=hashed_password)

with app.app_context():
    db.session.add(new_user)
    db.session.commit()
    print('User created successfully!')
