from flask import Flask, request, session, redirect, url_for, render_template, flash, jsonify
import boto3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import os
import uuid
from dotenv import load_dotenv
from decimal import Decimal, InvalidOperation
import json

# Load environment variables
load_dotenv()

# ---------------------------------------
# Flask App Initialization
# ---------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'cropyield_secret_key_2024')

# ---------------------------------------
# App Configuration
# ---------------------------------------
AWS_REGION_NAME = os.environ.get('AWS_REGION_NAME', 'us-east-1')

# Email Configuration
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SENDER_EMAIL = os.environ.get('SENDER_EMAIL')
SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD')
ENABLE_EMAIL = os.environ.get('ENABLE_EMAIL', 'False').lower() == 'true'

# Table Names from .env
USERS_TABLE_NAME = os.environ.get('USERS_TABLE_NAME', 'CropYieldUsers')
FIELDS_TABLE_NAME = os.environ.get('FIELDS_TABLE_NAME', 'CropFields')
YIELDS_TABLE_NAME = os.environ.get('YIELDS_TABLE_NAME', 'CropYields')
WEATHER_TABLE_NAME = os.environ.get('WEATHER_TABLE_NAME', 'WeatherData')

# SNS Configuration
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
ENABLE_SNS = os.environ.get('ENABLE_SNS', 'False').lower() == 'true'

# ---------------------------------------
# AWS Resources
# ---------------------------------------
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION_NAME)
sns = boto3.client('sns', region_name=AWS_REGION_NAME)

# DynamoDB Tables
users_table = dynamodb.Table(USERS_TABLE_NAME)
fields_table = dynamodb.Table(FIELDS_TABLE_NAME)
yields_table = dynamodb.Table(YIELDS_TABLE_NAME)
weather_table = dynamodb.Table(WEATHER_TABLE_NAME)

# ---------------------------------------
# Logging
# ---------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("cropyield.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ---------------------------------------
# Helper Functions
# ---------------------------------------
def safe_decimal_to_float(value):
    """Safely convert Decimal to float"""
    if value is None:
        return 0.0
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except (ValueError, TypeError):
        return 0.0

def safe_to_decimal(value):
    """Safely convert value to Decimal for DynamoDB storage"""
    if value is None:
        return Decimal('0')
    if isinstance(value, Decimal):
        return value
    try:
        return Decimal(str(value))
    except (ValueError, TypeError, InvalidOperation):
        return Decimal('0')

def is_logged_in():
    return 'email' in session

def get_user_role(email):
    try:
        response = users_table.get_item(Key={'email': email})
        return response.get('Item', {}).get('role')
    except Exception as e:
        logger.error(f"Error fetching role: {e}")
    return None

def send_email(to_email, subject, body):
    if not ENABLE_EMAIL:
        logger.info(f"[Email Skipped] Subject: {subject} to {to_email}")
        return

    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, to_email, msg.as_string())
        server.quit()

        logger.info(f"Email sent to {to_email}")
    except Exception as e:
        logger.error(f"Email sending failed: {e}")

def publish_to_sns(message, subject="Crop Yield Alert"):
    if not ENABLE_SNS:
        logger.info("[SNS Skipped] Message: {}".format(message))
        return

    try:
        response = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject=subject
        )
        logger.info(f"SNS published: {response['MessageId']}")
    except Exception as e:
        logger.error(f"SNS publish failed: {e}")

def require_role(required_role):
    def decorator(f):
        def decorated_function(*args, **kwargs):
            if not is_logged_in():
                flash('Please log in to access this page', 'warning')
                return redirect(url_for('login'))
            
            user_role = session.get('role')
            if user_role != required_role and required_role != 'any':
                flash('Access denied. Insufficient permissions.', 'danger')
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        decorated_function.__name__ = f.__name__
        return decorated_function
    return decorator

# ---------------------------------------
# Context Processors
# ---------------------------------------
@app.context_processor
def inject_now():
    """Inject current date/time into all templates"""
    return {
        'now': datetime.now(),
        'today': datetime.now().strftime('%Y-%m-%d'),
        'current_year': datetime.now().year
    }

# ---------------------------------------
# Routes
# ---------------------------------------

# Home Page
@app.route('/')
def index():
    if is_logged_in():
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# User Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if is_logged_in():
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        required_fields = ['name', 'email', 'password', 'role']
        for field in required_fields:
            if field not in request.form or not request.form[field]:
                flash(f'Please fill in the {field} field', 'danger')
                return render_template('register.html')
        
        if request.form['password'] != request.form.get('confirm_password', ''):
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
        
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']  # 'farmer', 'agronomist', 'admin'
        phone = request.form.get('phone', '')
        farm_name = request.form.get('farm_name', '')
        
        # Check if user already exists
        existing_user = users_table.get_item(Key={'email': email}).get('Item')
        if existing_user:
            flash('Email already registered', 'danger')
            return render_template('register.html')

        user_item = {
            'email': email,
            'name': name,
            'password': password,
            'role': role,
            'phone': phone,
            'login_count': 0,
            'status': 'active',
            'created_at': datetime.now().isoformat(),
        }
        
        if role == 'farmer' and farm_name:
            user_item['farm_name'] = farm_name
        
        users_table.put_item(Item=user_item)
        
        welcome_msg = f"Welcome to Crop Yield Management System, {name}! Your {role} account has been created successfully."
        send_email(email, "Welcome to Crop Yield System", welcome_msg)
        
        publish_to_sns(f'New {role} registered: {name} ({email})', 'New User Registration')
        
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in():
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Email and password are required', 'danger')
            return render_template('login.html')

        user = users_table.get_item(Key={'email': email}).get('Item')

        if user and check_password_hash(user['password'], password):
            if user.get('status') != 'active':
                flash('Account is inactive. Contact administrator.', 'warning')
                return render_template('login.html')
                
            session['email'] = email
            session['role'] = user['role']
            session['name'] = user.get('name', '')
            
            # Update login count
            try:
                users_table.update_item(
                    Key={'email': email},
                    UpdateExpression='SET login_count = if_not_exists(login_count, :zero) + :inc, last_login = :now',
                    ExpressionAttributeValues={
                        ':inc': 1, 
                        ':zero': 0, 
                        ':now': datetime.now().isoformat()
                    }
                )
            except Exception as e:
                logger.error(f"Failed to update login info: {e}")
            
            flash(f'Welcome back, {user.get("name", "")}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html')

# Dashboard
@app.route('/dashboard')
@require_role('any')
def dashboard():
    user_role = session.get('role')
    email = session.get('email')
    
    dashboard_data = {
        'role': user_role,
        'name': session.get('name'),
        'email': email
    }
    
    try:
        if user_role == 'farmer':
            # Get farmer's fields and recent yields
            fields_response = fields_table.scan(
                FilterExpression='owner_email = :owner',
                ExpressionAttributeValues={':owner': email}
            )
            dashboard_data['total_fields'] = len(fields_response.get('Items', []))
            dashboard_data['my_fields'] = fields_response.get('Items', [])
            
        elif user_role == 'agronomist':
            # Get system overview for agronomist
            fields_response = fields_table.scan()
            dashboard_data['total_fields'] = len(fields_response.get('Items', []))
            
        elif user_role == 'admin':
            # Get full system overview
            users_response = users_table.scan()
            fields_response = fields_table.scan()
            dashboard_data['total_users'] = len(users_response.get('Items', []))
            dashboard_data['total_fields'] = len(fields_response.get('Items', []))
            
    except Exception as e:
        logger.error(f"Dashboard data fetch error: {e}")
        flash('Error loading dashboard data', 'warning')
    
    return render_template('dashboard.html', data=dashboard_data)

# Field Management
@app.route('/fields')
@require_role('any')
def fields():
    try:
        if session.get('role') == 'farmer':
            # Farmers see only their fields
            response = fields_table.scan(
                FilterExpression='owner_email = :owner',
                ExpressionAttributeValues={':owner': session.get('email')}
            )
        else:
            # Agronomists and admins see all fields
            response = fields_table.scan()
        
        fields_list = response.get('Items', [])
        
        # Process fields to handle Decimal values
        for field in fields_list:
            if 'area_hectares' in field:
                field['area_hectares'] = safe_decimal_to_float(field['area_hectares'])
        
        return render_template('fields.html', fields=fields_list)
    except Exception as e:
        logger.error(f"Error fetching fields: {e}")
        flash('Error loading fields', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/add_field', methods=['GET', 'POST'])
@require_role('farmer')
def add_field():
    if request.method == 'POST':
        required_fields = ['field_name', 'location', 'area_hectares', 'soil_type']
        for field in required_fields:
            if not request.form.get(field):
                flash(f'Please fill in the {field} field', 'danger')
                return render_template('add_field.html')
        
        field_id = str(uuid.uuid4())
        
        field_item = {
            'field_id': field_id,
            'field_name': request.form['field_name'],
            'location': request.form['location'],
            'area_hectares': safe_to_decimal(request.form['area_hectares']),
            'soil_type': request.form['soil_type'],
            'crop_type': request.form.get('crop_type', ''),
            'irrigation_type': request.form.get('irrigation_type', 'rain-fed'),
            'owner_email': session.get('email'),
            'owner_name': session.get('name'),
            'status': 'active',
            'created_at': datetime.now().isoformat(),
        }
        
        fields_table.put_item(Item=field_item)
        
        publish_to_sns(
            f'New field registered: {field_item["field_name"]} by {session.get("name")} ({safe_decimal_to_float(field_item["area_hectares"])} hectares)',
            'New Field Added'
        )
        
        flash('Field added successfully', 'success')
        return redirect(url_for('fields'))
    
    return render_template('add_field.html')

# Yield Data Management
@app.route('/yields')
@require_role('any')
def yields():
    try:
        if session.get('role') == 'farmer':
            # Get farmer's fields first, then their yields
            fields_response = fields_table.scan(
                FilterExpression='owner_email = :owner',
                ExpressionAttributeValues={':owner': session.get('email')}
            )
            farmer_field_ids = [field['field_id'] for field in fields_response.get('Items', [])]
            
            # Get yields for farmer's fields
            yields_list = []
            for field_id in farmer_field_ids:
                try:
                    field_yields = yields_table.scan(
                        FilterExpression='field_id = :field_id',
                        ExpressionAttributeValues={':field_id': field_id}
                    )
                    yields_list.extend(field_yields.get('Items', []))
                except Exception as e:
                    logger.error(f"Error fetching yields for field {field_id}: {e}")
        else:
            # Agronomists and admins see all yields
            response = yields_table.scan()
            yields_list = response.get('Items', [])
        
        # Process yields to handle Decimal values
        for yield_record in yields_list:
            decimal_fields = ['yield_per_hectare', 'total_yield', 'quality_score']
            for field in decimal_fields:
                if field in yield_record:
                    yield_record[field] = safe_decimal_to_float(yield_record[field])
        
        # Sort by harvest date (most recent first)
        yields_list.sort(key=lambda x: x.get('harvest_date', ''), reverse=True)
        
        return render_template('yields.html', yields=yields_list)
    except Exception as e:
        logger.error(f"Error fetching yields: {e}")
        flash('Error loading yield data', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/record_yield', methods=['GET', 'POST'])
@require_role('farmer')
def record_yield():
    if request.method == 'POST':
        required_fields = ['field_id', 'crop_type', 'harvest_date', 'yield_per_hectare']
        for field in required_fields:
            if not request.form.get(field):
                flash(f'Please fill in the {field} field', 'danger')
                # Reload fields for error case
                try:
                    fields_response = fields_table.scan(
                        FilterExpression='owner_email = :owner AND #status = :status',
                        ExpressionAttributeNames={'#status': 'status'},
                        ExpressionAttributeValues={':owner': session.get('email'), ':status': 'active'}
                    )
                    fields_list = fields_response.get('Items', [])
                except Exception as e:
                    fields_list = []
                return render_template('record_yield.html', fields=fields_list)
        
        yield_id = str(uuid.uuid4())
        field_id = request.form['field_id']
        
        # Get field info to calculate total yield
        field_info = fields_table.get_item(Key={'field_id': field_id}).get('Item', {})
        area_hectares = safe_decimal_to_float(field_info.get('area_hectares', 1))
        yield_per_hectare = safe_to_decimal(request.form['yield_per_hectare'])
        total_yield = safe_to_decimal(float(yield_per_hectare) * area_hectares)
        
        yield_item = {
            'yield_id': yield_id,
            'field_id': field_id,
            'field_name': field_info.get('field_name', ''),
            'crop_type': request.form['crop_type'],
            'harvest_date': request.form['harvest_date'],
            'yield_per_hectare': yield_per_hectare,
            'total_yield': total_yield,
            'quality_score': safe_to_decimal(request.form.get('quality_score', 0)),
            'weather_conditions': request.form.get('weather_conditions', ''),
            'notes': request.form.get('notes', ''),
            'farmer_email': session.get('email'),
            'farmer_name': session.get('name'),
            'recorded_at': datetime.now().isoformat(),
        }
        
        yields_table.put_item(Item=yield_item)
        
        # Check for yield anomalies and send alerts
        avg_yield = 3.5  # This could be calculated from historical data
        current_yield = safe_decimal_to_float(yield_per_hectare)
        
        if current_yield < avg_yield * 0.7:  # 30% below average
            alert_msg = f"Low yield alert: {field_info.get('field_name', field_id)} produced {current_yield} tons/hectare, which is significantly below average"
            publish_to_sns(alert_msg, 'Yield Anomaly Alert')
        elif current_yield > avg_yield * 1.3:  # 30% above average
            alert_msg = f"Excellent yield: {field_info.get('field_name', field_id)} produced {current_yield} tons/hectare, exceeding expectations"
            publish_to_sns(alert_msg, 'High Yield Report')
        
        flash('Yield data recorded successfully', 'success')
        return redirect(url_for('yields'))
    
    # GET request - load farmer's fields
    try:
        fields_response = fields_table.scan(
            FilterExpression='owner_email = :owner AND #status = :status',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':owner': session.get('email'), ':status': 'active'}
        )
        fields_list = fields_response.get('Items', [])
        
        if not fields_list:
            flash('You need to add fields before recording yields', 'warning')
            return redirect(url_for('add_field'))
            
    except Exception as e:
        logger.error(f"Error fetching farmer's fields: {e}")
        fields_list = []
        flash('Error loading fields', 'danger')
    
    return render_template('record_yield.html', fields=fields_list)

# Weather Data Management
@app.route('/weather')
@require_role('any')
def weather():
    try:
        response = weather_table.scan()
        weather_list = response.get('Items', [])
        
        # Process weather data to handle Decimal values
        for weather_record in weather_list:
            decimal_fields = ['temperature', 'humidity', 'rainfall', 'wind_speed']
            for field in decimal_fields:
                if field in weather_record:
                    weather_record[field] = safe_decimal_to_float(weather_record[field])
        
        # Sort by date (most recent first)
        weather_list.sort(key=lambda x: x.get('date', ''), reverse=True)
        
        return render_template('weather.html', weather_data=weather_list)
    except Exception as e:
        logger.error(f"Error fetching weather data: {e}")
        flash('Error loading weather data', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/add_weather', methods=['GET', 'POST'])
@require_role('agronomist')
def add_weather():
    if request.method == 'POST':
        required_fields = ['location', 'date', 'temperature', 'humidity', 'rainfall']
        for field in required_fields:
            if not request.form.get(field):
                flash(f'Please fill in the {field} field', 'danger')
                return render_template('add_weather.html')
        
        weather_id = str(uuid.uuid4())
        
        weather_item = {
            'weather_id': weather_id,
            'location': request.form['location'],
            'date': request.form['date'],
            'temperature': safe_to_decimal(request.form['temperature']),
            'humidity': safe_to_decimal(request.form['humidity']),
            'rainfall': safe_to_decimal(request.form['rainfall']),
            'wind_speed': safe_to_decimal(request.form.get('wind_speed', 0)),
            'weather_condition': request.form.get('weather_condition', 'clear'),
            'recorded_by': session.get('email'),
            'created_at': datetime.now().isoformat(),
        }
        
        weather_table.put_item(Item=weather_item)
        
        # Check for extreme weather and send alerts
        temp = safe_decimal_to_float(weather_item['temperature'])
        rainfall = safe_decimal_to_float(weather_item['rainfall'])
        
        if temp > 40:
            publish_to_sns(f"High temperature alert: {temp}°C recorded at {weather_item['location']}", 'Weather Alert')
        elif temp < 0:
            publish_to_sns(f"Frost alert: {temp}°C recorded at {weather_item['location']}", 'Weather Alert')
        
        if rainfall > 100:
            publish_to_sns(f"Heavy rainfall alert: {rainfall}mm recorded at {weather_item['location']}", 'Weather Alert')
        
        flash('Weather data added successfully', 'success')
        return redirect(url_for('weather'))
    
    return render_template('add_weather.html')

# Admin Routes
@app.route('/admin/users')
@require_role('admin')
def admin_users():
    try:
        response = users_table.scan()
        users_list = response.get('Items', [])
        return render_template('admin_users.html', users=users_list)
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        flash('Error loading users', 'danger')
        return redirect(url_for('dashboard'))

# API Routes
@app.route('/api/field_summary/<field_id>')
@require_role('any')
def api_field_summary(field_id):
    try:
        # Get field info
        field = fields_table.get_item(Key={'field_id': field_id}).get('Item')
        if not field:
            return jsonify({'status': 'error', 'message': 'Field not found'}), 404
        
        # Get recent yields for this field
        yields_response = yields_table.scan(
            FilterExpression='field_id = :field_id',
            ExpressionAttributeValues={':field_id': field_id}
        )
        yields_list = yields_response.get('Items', [])
        
        # Calculate average yield
        if yields_list:
            avg_yield = sum(safe_decimal_to_float(y.get('yield_per_hectare', 0)) for y in yields_list) / len(yields_list)
        else:
            avg_yield = 0
        
        return jsonify({
            'status': 'success',
            'data': {
                'field_name': field['field_name'],
                'area_hectares': safe_decimal_to_float(field.get('area_hectares', 0)),
                'crop_type': field.get('crop_type', ''),
                'total_harvests': len(yields_list),
                'average_yield': round(avg_yield, 2)
            }
        })
    except Exception as e:
        logger.error(f"API error: {e}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

# Template Filters
@app.template_filter('timeago')
def timeago_filter(date_str):
    """Convert ISO date string to human readable time ago format"""
    if not date_str:
        return "Never"
    
    try:
        date = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        now = datetime.now()
        diff = now - date
        
        if diff.days > 0:
            if diff.days == 1:
                return "1 day ago"
            elif diff.days < 7:
                return f"{diff.days} days ago"
            elif diff.days < 30:
                weeks = diff.days // 7
                return f"{weeks} week{'s' if weeks > 1 else ''} ago"
            else:
                months = diff.days // 30
                return f"{months} month{'s' if months > 1 else ''} ago"
        else:
            hours = diff.seconds // 3600
            if hours > 0:
                return f"{hours} hour{'s' if hours > 1 else ''} ago"
            else:
                minutes = diff.seconds // 60
                if minutes > 0:
                    return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
                else:
                    return "Just now"
    except:
        return date_str[:10]

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

# Run the application
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)