import os
import uuid
from math import radians, sin, cos, sqrt, atan2

from flask import Flask, request, jsonify, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import webauthn
from webauthn.helpers.structs import RegistrationCredential, AuthenticationCredential
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers import options_to_json, base64url_to_bytes, bytes_to_base64url

app = Flask(__name__, static_folder='../frontend/static', static_url_path='/static')
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///attendance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# --- Database Models ---

class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_handle = db.Column(db.String(64), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    credentials = db.relationship('Credential', backref='employee', lazy=True)

class Credential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    credential_id = db.Column(db.LargeBinary, unique=True, nullable=False)
    public_key = db.Column(db.LargeBinary, nullable=False)
    sign_count = db.Column(db.Integer, default=0)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)

class AttendanceRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    employee = db.relationship('Employee')

# --- WebAuthn Configuration ---

RP_ID = 'localhost'
RP_NAME = 'Attendance System'
ORIGIN = 'http://127.0.0.1:5000'

# --- Office Location ---
OFFICE_LATITUDE = 37.7749
OFFICE_LONGITUDE = -122.4194
ALLOWED_DISTANCE_METERS = 100

def get_employee_by_username(username):
    return Employee.query.filter_by(username=username).first()

def get_employee_by_user_handle(user_handle):
    return Employee.query.filter_by(user_handle=user_handle).first()

def get_credentials_by_employee_id(employee_id):
    return Credential.query.filter_by(employee_id=employee_id).all()

def distance(lat1, lon1, lat2, lon2):
    R = 6371e3  # metres
    phi1 = radians(lat1)
    phi2 = radians(lat2)
    delta_phi = radians(lat2 - lat1)
    delta_lambda = radians(lon2 - lon1)

    a = sin(delta_phi / 2)**2 + cos(phi1) * cos(phi2) * sin(delta_lambda / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))

    return R * c

@app.route('/register/start', methods=['POST'])
def register_start():
    data = request.get_json()
    username = data.get('username')

    if not username:
        return jsonify({'error': 'Username is required'}), 400

    if get_employee_by_username(username):
        return jsonify({'error': 'Username already exists'}), 400

    user_handle = str(uuid.uuid4())

    registration_options = webauthn.generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user_handle.encode('utf-8'),
        user_name=username,
        user_display_name=username,
    )

    session['challenge'] = registration_options.challenge
    session['username'] = username
    session['user_handle'] = user_handle

    return jsonify(options_to_json(registration_options))

@app.route('/register/finish', methods=['POST'])
def register_finish():
    credential = request.get_json()
    challenge = session.get('challenge')
    username = session.get('username')
    user_handle = session.get('user_handle')

    if not all([credential, challenge, username, user_handle]):
        return jsonify({'error': 'Missing required session data'}), 400

    try:
        registration_verification = webauthn.verify_registration_response(
            credential=RegistrationCredential.parse_raw(request.data),
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
        )
    except Exception as e:
        return jsonify({'error': f'Registration failed: {e}'}), 400

    new_employee = Employee(username=username, user_handle=user_handle)
    db.session.add(new_employee)
    db.session.commit()

    new_credential = Credential(
        credential_id=registration_verification.credential_id,
        public_key=registration_verification.credential_public_key,
        sign_count=registration_verification.sign_count,
        employee_id=new_employee.id,
    )
    db.session.add(new_credential)
    db.session.commit()

    session.pop('challenge', None)
    session.pop('username', None)
    session.pop('user_handle', None)

    return jsonify({'success': True, 'username': username})

@app.route('/login/start', methods=['POST'])
def login_start():
    data = request.get_json()
    username = data.get('username')

    if not username:
        return jsonify({'error': 'Username is required'}), 400

    employee = get_employee_by_username(username)
    if not employee:
        return jsonify({'error': 'User not found'}), 404

    credentials = get_credentials_by_employee_id(employee.id)
    if not credentials:
        return jsonify({'error': 'No credentials found for this user'}), 404

    authentication_options = webauthn.generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[{'id': cred.credential_id} for cred in credentials],
    )

    session['challenge'] = authentication_options.challenge

    return jsonify(options_to_json(authentication_options))

@app.route('/login/finish', methods=['POST'])
def login_finish():
    data = request.get_json()
    credential = data.get('credential')
    location = data.get('location')

    if not credential or not location:
        return jsonify({'error': 'Credential and location are required'}), 400

    lat = location.get('latitude')
    lon = location.get('longitude')

    if not lat or not lon:
        return jsonify({'error': 'Latitude and longitude are required'}), 400

    dist = distance(lat, lon, OFFICE_LATITUDE, OFFICE_LONGITUDE)
    if dist > ALLOWED_DISTANCE_METERS:
        return jsonify({'error': f'You are {dist:.0f} meters away from the office. You must be within {ALLOWED_DISTANCE_METERS} meters to clock in.'}), 403

    challenge = session.get('challenge')
    if not challenge:
        return jsonify({'error': 'Missing challenge from session'}), 400

    try:
        auth_credential = AuthenticationCredential.parse_raw(str(credential).replace("'", "\""))
        user_handle = auth_credential.response.user_handle

        employee = get_employee_by_user_handle(user_handle.decode('utf-8'))
        if not employee:
            return jsonify({'error': 'User not found'}), 404

        db_credential = Credential.query.filter_by(credential_id=auth_credential.id).first()
        if not db_credential:
            return jsonify({'error': 'Credential not found'}), 404

        authentication_verification = webauthn.verify_authentication_response(
            credential=auth_credential,
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=db_credential.public_key,
            credential_current_sign_count=db_credential.sign_count,
        )

        db_credential.sign_count = authentication_verification.new_sign_count
        db.session.commit()

        attendance_record = AttendanceRecord(employee_id=employee.id)
        db.session.add(attendance_record)
        db.session.commit()

        session.pop('challenge', None)

        return jsonify({'success': True, 'username': employee.username})

    except Exception as e:
        return jsonify({'error': f'Authentication failed: {e}'}), 400

@app.route('/')
def index():
    return send_from_directory('../frontend', 'index.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
