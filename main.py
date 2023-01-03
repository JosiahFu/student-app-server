import hashlib

from flask import Flask, request

app = Flask(__name__)

# Dictionary to store data for each user
data = {}

# Dictionary to store password hashes for each user
passwords = {}

def hash_password(password):
    """
    Hash a password using SHA-256.
    """
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/data', methods=['POST'])
def add_data():
    """
    Add data for a user.
    """
    # Get JSON data from request
    new_data = request.get_json()

    # Get user and password from data
    user = new_data.get('user')
    if user is None:
        return 'Missing user field in request data', 400
    password = new_data.get('password')
    if password is None:
        return 'Missing password field in request data', 400

    # Hash password
    password_hash = hash_password(password)

    # Check if user exists and if password is correct
    stored_password_hash = passwords.get(user)
    if stored_password_hash is None:
        # User does not exist, add password hash to passwords dictionary
        passwords[user] = password_hash
    elif password_hash != stored_password_hash:
        # User exists, but provided password is incorrect
        return 'Incorrect password', 401

    # Get data from request
    user_data = new_data.get('data')
    if user_data is None:
        return 'Missing data field in request data', 400

    # Update data for user
    existing_user_data = data.get(user)
    if existing_user_data is None:
        # User does not have any data yet, add data to data dictionary
        data[user] = user_data
    else:
        # User has existing data, merge new data with existing data
        existing_user_data.update(user_data)

    return 'Data added successfully', 201

@app.route('/data', methods=['GET'])
def get_data():
    """
    Get data for a user.
    """
    # Get user and password from query string
    user = request.args.get('user')
    if user is None:
        return 'Missing user field in query string', 400
    password = request.args.get('password')
    if password is None:
        return 'Missing password field in query string', 400

    # Hash password
    password_hash = hash_password(password)

    # Check if user exists and if password is correct
    stored_password_hash = passwords.get(user)
    if stored_password_hash is None:
        # User does not exist
        return 'User not found', 404
    if password_hash != stored_password_hash:
        # Provided password is incorrect
        return 'Incorrect password', 401

    # Get user data
    user_data = data.get(user)

    # Get path from query string
    path = request.args.get('path')
    if path is None:
        # Return entire data dictionary if no path is provided
        return user_data, 200

    # Split path into parts
    path_parts = path.split('.')

    # Traverse data dictionary to get value at path
    curr = user_data
    for part in path_parts:
        if part not in curr:
            # Return 404 if path does not exist
            return 'Path not found', 404
        curr = curr[part]

    return curr, 200

if __name__ == '__main__':
    app.run()
