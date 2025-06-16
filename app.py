from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from dotenv import load_dotenv
import os
import requests
from datetime import datetime, timezone
from dateutil import parser

import firebase_admin
from firebase_admin import credentials, firestore

import google.auth.transport.requests
from google.oauth2 import id_token

load_dotenv()

app = Flask(__name__)
app.secret_key = 'forecastflow-secret'

FIREBASE_API_KEY = os.getenv("FIREBASE_API_KEY")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred)

db = firestore.client()


@app.route('/')
@app.route('/home', methods=['GET'])
def login_page():
    return render_template('home.html')


@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up_page():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={FIREBASE_API_KEY}"
        response = requests.post(url, json={
            "email": email,
            "password": password,
            "returnSecureToken": True
        }).json()

        if "idToken" in response:
            session['user'] = {
                'email': email,
                'name': name,
                'unit': "C"
            }

            db.collection("users").document(email).set({
                "name": name,
                "email": email,
                "unit": "C",
                "locations": [],
                "alerts": []
            }, merge=True)

            return redirect(url_for('login_page'))
        else:
            error_message = response.get('error', {}).get('message', 'Signup failed')
            return f"Signup failed: {error_message}"

    return render_template('sign_up.html')


@app.route('/home', methods=['POST'])
def login_user():
    email = request.form['email']
    password = request.form['password']

    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
    response = requests.post(url, json={
        "email": email,
        "password": password,
        "returnSecureToken": True
    }).json()

    if "idToken" in response:
        user_doc = db.collection("users").document(email).get()
        user_data = user_doc.to_dict() if user_doc.exists else {}
        user_name = user_data.get("name", "User")
        unit = user_data.get("unit", "C")

        session['user'] = {
            'email': email,
            'name': user_name,
            'unit': unit
        }

        return redirect(url_for('dashboard'))
    else:
        error_message = response.get('error', {}).get('message', 'Login failed')
        return f"Login failed: {error_message}"


@app.route('/google_login', methods=['POST'])
def google_login():
    data = request.get_json()
    token = data.get('credential')

    try:
        id_info = id_token.verify_oauth2_token(
            token,
            google.auth.transport.requests.Request(),
            GOOGLE_CLIENT_ID
        )

        email = id_info['email']
        name = id_info.get('name', 'User')

        user_ref = db.collection("users").document(email)
        if not user_ref.get().exists:
            user_ref.set({
                "name": name,
                "email": email,
                "provider": "google",
                "unit": "C"
            })

        session['user'] = {
            'email': email,
            'name': name,
            'unit': "C"
        }

        return jsonify({'success': True})

    except ValueError as e:
        print("Google Login Error:", e)
        return jsonify({'success': False})


@app.route('/index')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login_page'))
    return render_template('index.html', user=session['user'])


@app.route('/get_unit')
def get_unit():
    if 'user' not in session:
        return jsonify({'unit': 'C'})
    email = session['user']['email']
    user_doc = db.collection("users").document(email).get()
    if user_doc.exists:
        return jsonify({'unit': user_doc.to_dict().get("unit", "C")})
    return jsonify({'unit': 'C'})


@app.route('/set_unit', methods=['POST'])
def set_unit():
    if 'user' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'}), 403

    new_unit = request.json.get("unit", "C")
    email = session['user']['email']
    db.collection("users").document(email).update({"unit": new_unit})
    session['user']['unit'] = new_unit
    return jsonify({'success': True})


@app.route('/update_recent_search', methods=['POST'])
def update_recent_search():
    if 'user' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'}), 403

    data = request.get_json()
    new_city = data.get("city")
    new_temp = data.get("temp")
    new_condition = data.get("condition")
    current_city = data.get("current_city")

    if not all([new_city, new_temp, new_condition]):
        return jsonify({'success': False, 'error': 'Invalid data'}), 400

    email = session['user']['email']
    user_ref = db.collection("users").document(email)
    user_doc = user_ref.get()

    existing = user_doc.to_dict().get("recentSearches", []) if user_doc.exists else []

    new_city_lower = new_city.lower()
    current_city_lower = current_city.lower()

    filtered = [
        item for item in existing
        if item["city"].lower() != new_city_lower and item["city"].lower() != current_city_lower
    ]

    new_entry = {"city": new_city, "temp": new_temp, "condition": new_condition}
    updated = [new_entry] + filtered[:3]

    user_ref.update({"recentSearches": updated})
    return jsonify({'success': True})


@app.route('/get_recent_searches', methods=['GET'])
def get_recent_searches():
    if 'user' not in session:
        return jsonify([])

    email = session['user']['email']
    user_doc = db.collection("users").document(email).get()
    recent = user_doc.to_dict().get("recentSearches", []) if user_doc.exists else []
    return jsonify(recent)

@app.route('/toggle_location', methods=['POST'])
def toggle_location():
    if 'user' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'}), 403

    data = request.get_json()
    city = data.get("city")
    temp = data.get("temp")
    condition = data.get("condition")

    if not all([city, temp, condition]):
        return jsonify({'success': False, 'error': 'Missing data'}), 400

    email = session['user']['email'].strip().lower()
    user_ref = db.collection("users").document(email)
    user_doc = user_ref.get()
    existing = user_doc.to_dict().get("locations", []) if user_doc.exists else []

    city_lower = city.lower()
    found = False
    updated = []

    for entry in existing:
        if isinstance(entry, dict) and entry.get("city", "").lower() == city_lower:
            found = True
            continue 
        updated.append(entry)

    if found:
        user_ref.update({"locations": updated})
        return jsonify({'success': True, 'action': 'unpinned'})
    else:
        if len(existing) >= 8:
            return jsonify({'success': False, 'message': 'Maximum 8 locations allowed'})
        new_entry = {"city": city, "temp": temp, "condition": condition}
        updated = [new_entry] + existing
        user_ref.update({"locations": updated[:8]})
        return jsonify({'success': True, 'action': 'pinned'})

    
@app.route('/get_saved_locations', methods=['GET'])
def get_saved_locations():
    if 'user' not in session:
        return jsonify([])

    email = session['user']['email'].strip().lower()
    user_doc = db.collection("users").document(email).get()

    if not user_doc.exists:
        return jsonify([])

    saved = user_doc.to_dict().get("locations", [])
    return jsonify(saved)

@app.route('/toggle_alert_location', methods=['POST'])
def toggle_alert_location():
    if 'user' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'}), 403

    city = request.json.get("city")
    if not city:
        return jsonify({'success': False, 'error': 'No city provided'}), 400

    email = session['user']['email']
    user_ref = db.collection("users").document(email)
    user_doc = user_ref.get()

    existing = user_doc.to_dict().get("alerts", []) if user_doc.exists else []
    city_lower_list = [c.lower() for c in existing]

    if city.lower() in city_lower_list:
        updated = [loc for loc in existing if loc.lower() != city.lower()]
        user_ref.update({"alerts": updated})
        return jsonify({'success': True, 'action': 'removed'})
    else:
        updated = existing + [city]
        user_ref.update({"alerts": updated})
        return jsonify({'success': True, 'action': 'added'})
    
@app.route('/get_alert_cities', methods=['GET'])
def get_alert_cities():
    if 'user' not in session:
        return jsonify([])

    email = session['user']['email']
    user_doc = db.collection("users").document(email).get()
    if not user_doc.exists:
        return jsonify([])

    alert_cities = user_doc.to_dict().get("alerts", [])
    return jsonify(alert_cities)


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login_page'))


if __name__ == '__main__':
    app.run(debug=True)
