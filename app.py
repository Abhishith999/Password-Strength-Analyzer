from flask import Flask, request, render_template
import re
import sqlite3
import bcrypt
import secrets
import string

app = Flask(__name__)

# --- 1. Database Setup ---
def init_db():
    """Creates a local database file and the history table if they don't exist."""
    conn = sqlite3.connect('security_test.db')
    cursor = conn.cursor()
    # Create our password history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            old_password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Run the setup once when the app starts
init_db()

# --- Load Banned Passwords ---
def load_banned_passwords(filepath):
    """Loads compromised passwords into a highly efficient Set."""
    try:
        with open(filepath, 'r') as file:
            # .strip() removes invisible spaces, .lower() makes it case-insensitive
            return set(line.strip().lower() for line in file)
    except FileNotFoundError:
        print(f"Warning: {filepath} not found. Running without wordlist.")
        return set()

# Load this into memory exactly once when the server starts
BANNED_WORDS = load_banned_passwords('wordlist.txt')

# --- 2. Core Logic ---
def evaluate_password_strength(password):
    """Checks the password against dictionaries, length, and complexity."""
    
    # 1. NEW: The Dictionary/Wordlist Check
    if password.lower() in BANNED_WORDS:
        # Instant failure!
        return 0,"Compromised (In Dictionary)", {
            "Not Common Password": False,
            "Length >= 8": len(password) >= 8,
            "Uppercase Letter": bool(re.search(r'[A-Z]', password)),
            "Lowercase Letter": bool(re.search(r'[a-z]', password)),
            "Number": bool(re.search(r'\d', password)),
            "Special Character": bool(re.search(r'[\W_]', password))
        }

    # 2. Existing Complexity Logic
    feedback = {
        "Not Common Password": True, # 1 point
        "Length >= 8": len(password) >= 8, # 1 point
        "Uppercase Letter": bool(re.search(r'[A-Z]', password)), # 1 point
        "Lowercase Letter": bool(re.search(r'[a-z]', password)), # 1 point
        "Number": bool(re.search(r'\d', password)), # 1 point
        "Special Character": bool(re.search(r'[\W_]', password)) # 1 point
    }
    
    # Just sum them directly! Max score is now 6.
    score = sum(feedback.values()) 
    
    # Update the thresholds for the new 6-point scale
    if score == 6: 
        label = "Very Strong"
    elif score >= 4: 
        label = "Strong"
    elif score >= 2: 
        label = "Moderate"
    else: 
        label = "Weak"
        
    return score, label, feedback

def check_and_save_database(new_password):
    """Checks for reuse. If safe, hashes and saves the new password."""
    # We will pretend the user is logged in as User #1 for this test
    current_user_id = 1 
    
    conn = sqlite3.connect('security_test.db')
    cursor = conn.cursor()
    
    # Check history
    cursor.execute("SELECT old_password_hash FROM password_history WHERE user_id = ?", (current_user_id,))
    historical_hashes = cursor.fetchall()
    
    for (stored_hash,) in historical_hashes:
        # Check if the new password matches any old hash
        if bcrypt.checkpw(new_password.encode('utf-8'), stored_hash.encode('utf-8')):
            conn.close()
            return False, "Database Alert: You cannot reuse a previous password!"
            
    # If no matches are found, it's a new password! Let's hash and save it.
    salt = bcrypt.gensalt()
    new_hash = bcrypt.hashpw(new_password.encode('utf-8'), salt).decode('utf-8')
    
    cursor.execute("INSERT INTO password_history (user_id, old_password_hash) VALUES (?, ?)", 
                   (current_user_id, new_hash))
    conn.commit()
    conn.close()
    
    return True, "Success: Secure hash saved to the database!"

# --- New Feature: Secure Password Generator ---
def generate_strong_password(length=16):
    """Generates a cryptographically secure, high-entropy password."""
    # Define our character categories using the 'string' module
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    
    # 1. Combine every single possible character into one giant pool
    all_characters = lower + upper + digits + special
    
    # 2. Guarantee complexity by forcing at least one character from each pool
    password_list = [
        secrets.choice(lower),
        secrets.choice(upper),
        secrets.choice(digits),
        secrets.choice(special)
    ]
    
    # 3. Fill up the rest of the password length randomly from the giant pool
    for _ in range(length - 4):
        password_list.append(secrets.choice(all_characters))
        
    # 4. Use a secure system randomizer to shuffle the characters.
    # This ensures the guaranteed characters aren't always at the front!
    secrets.SystemRandom().shuffle(password_list)
    
    # Join the list back into a single string text
    return "".join(password_list)
# --- 3. Web Routes ---
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    user_password = request.form.get('password') or ""
    
    # 1. Evaluate Complexity First (Input Validation)
    score, label, details = evaluate_password_strength(user_password)
    
    db_status = ""
    db_success = False
    
    # 2. Strict Security Policy: Only interact with the DB if the score is 5 or 6
    if score >= 5:
        # It's strong enough! Now check if it's a reused password and save it.
        db_success, db_status = check_and_save_database(user_password)
    else:
        # It failed validation. Block it completely.
        db_status = f"Policy Violation: '{label}' passwords are not permitted. It was rejected and not saved."
        db_success = False
        
    # 3. Generate a strong alternative 
    alternative = generate_strong_password(length=16)
    
    return render_template('index.html', 
                           password=user_password, 
                           score=score, 
                           label=label, 
                           details=details, 
                           db_status=db_status, 
                           db_success=db_success,
                           alternative=alternative)

if __name__ == '__main__':
    app.run(debug=True)