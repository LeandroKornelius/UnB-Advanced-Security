import sqlite3
import bcrypt
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'db.db')

def init_db():
    # Initialize the database and create the users table
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL, 
            password TEXT NOT NULL
        )
    ''')
    con.commit()
    con.close()

def user_exists(email):
    # Check if a user already exists by email.
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute('SELECT * FROM users WHERE email = ?', (email,))
        return cur.fetchone() is not None
    finally:
        con.close()

def add_user(email, password):
    # Checks if user exists
    if user_exists(email):
        return False  # User already exists

    # Hashes the password to increase security
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_password))
        con.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        con.close()

def get_user(email):
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute('SELECT email, password FROM users WHERE email = ?', (email,))
        user = cur.fetchone()
        con.close()
        return user
    except:
        return sqlite3.IntegrityError

def get_users_emails():
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute('SELECT email FROM users')
        users = [row[0] for row in cur.fetchall()]
        con.close()
        return users
    except:
        return sqlite3.IntegrityError

def check_user_password(email, password):
    user = get_user(email)
    if not user:
        return False
    stored_hash = user[1]
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash)

if __name__ == '__main__':
    init_db()
    print('🎲 Database is running')