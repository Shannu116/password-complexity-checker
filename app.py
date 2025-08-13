from flask import Flask, render_template, request, jsonify
import re
import requests
import os
import hashlib

app = Flask(__name__)

def password_complexity_checker(password):
    """
    Check password complexity based on multiple criteria
    Returns a dictionary with detailed analysis
    """
    requirements = {
        'length': 8,
        'uppercase': 1,
        'lowercase': 1,
        'digits': 1,
        'special_character': 1
    }
    
    analysis = {
        'is_strong': True,
        'score': 0,
        'max_score': 5,
        'feedback': [],
        'criteria': {
            'length': False,
            'uppercase': False,
            'lowercase': False,
            'digits': False,
            'special_character': False
        }
    }
    
    # Check length
    if len(password) >= requirements['length']:
        analysis['criteria']['length'] = True
        analysis['score'] += 1
    else:
        analysis['is_strong'] = False
        analysis['feedback'].append(f"Password must be at least {requirements['length']} characters long")
    
    # Check uppercase letters
    if re.search(r"[A-Z]", password):
        analysis['criteria']['uppercase'] = True
        analysis['score'] += 1
    else:
        analysis['is_strong'] = False
        analysis['feedback'].append("Password must contain at least 1 uppercase letter")
    
    # Check lowercase letters
    if re.search(r"[a-z]", password):
        analysis['criteria']['lowercase'] = True
        analysis['score'] += 1
    else:
        analysis['is_strong'] = False
        analysis['feedback'].append("Password must contain at least 1 lowercase letter")
    
    # Check digits
    if re.search(r"\d", password):
        analysis['criteria']['digits'] = True
        analysis['score'] += 1
    else:
        analysis['is_strong'] = False
        analysis['feedback'].append("Password must contain at least 1 digit")
    
    # Check special characters
    if re.search(r"\W", password):
        analysis['criteria']['special_character'] = True
        analysis['score'] += 1
    else:
        analysis['is_strong'] = False
        analysis['feedback'].append("Password must contain at least 1 special character")
    
    # Determine strength level
    if analysis['score'] == 5:
        analysis['strength_level'] = 'Very Strong'
        analysis['strength_color'] = '#00ff00'
    elif analysis['score'] == 4:
        analysis['strength_level'] = 'Strong'
        analysis['strength_color'] = '#90ee90'
    elif analysis['score'] == 3:
        analysis['strength_level'] = 'Moderate'
        analysis['strength_color'] = '#ffa500'
    elif analysis['score'] == 2:
        analysis['strength_level'] = 'Weak'
        analysis['strength_color'] = '#ff6b6b'
    else:
        analysis['strength_level'] = 'Very Weak'
        analysis['strength_color'] = '#ff0000'
    
    return analysis

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check_password', methods=['POST'])
def check_password():
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        if not password:
            return jsonify({'error': 'Password is required'})
        
        analysis = password_complexity_checker(password)
        return jsonify(analysis)
        
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/check_breach', methods=['POST'])
def check_breach():
    data = request.get_json()
    password = data.get('password')
    api_key = data.get('api_key')  # Get API key from request
    
    if not password:
        return jsonify({'error': 'Password not provided.'}), 400

    if not api_key:
        return jsonify({'error': 'API key not provided.'}), 400

    # Hash the password using SHA-1
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    hash_prefix = sha1_hash[:5]
    hash_suffix = sha1_hash[5:]

    url = f'https://api.pwnedpasswords.com/range/{hash_prefix}'
    headers = {
        'Add-Padding': 'true',
        'hibp-api-key': api_key,
        'User-Agent': 'PasswordBreachChecker'
    }

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 401:
            return jsonify({'error': 'Invalid API key.'}), 401
        elif response.status_code != 200:
            return jsonify({'error': f'API error: {response.status_code}'}), response.status_code

        hashes = response.text.splitlines()
        for h in hashes:
            if ':' in h:
                hash_part, count = h.split(':')
                if hash_part == hash_suffix:
                    return jsonify({'breached': True, 'count': int(count)})

        return jsonify({'breached': False})
    
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Network error: {str(e)}'}), 500

@app.route('/check_rockyou', methods=['POST'])
def check_rockyou():
    data = request.get_json()
    password = data.get('password')
    
    if not password:
        return jsonify({'error': 'Password not provided.'}), 400

    try:
        # Check if rockyou.txt exists
        rockyou_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rockyou.txt')
        
        if not os.path.exists(rockyou_path):
            return jsonify({
                'error': 'Local password database not available. Please use the HIBP API option for breach checking.',
                'suggestion': 'Get a free API key from Have I Been Pwned to check against their comprehensive database.'
            }), 404
        
        with open(rockyou_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                if line.strip() == password:
                    return jsonify({'found': True, 'line_number': line_num})
        return jsonify({'found': False})
        
    except Exception as e:
        return jsonify({'error': f'Error reading local database: {str(e)}'}), 500

@app.route('/health')
def health_check():
    """Health check endpoint for deployment platforms"""
    return jsonify({
        'status': 'healthy',
        'service': 'Password Complexity Checker',
        'version': '2.0'
    }), 200

if __name__ == '__main__':
    # Railway deployment configuration
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV', 'production') != 'production'
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug_mode
    )
