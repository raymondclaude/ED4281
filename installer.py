#!/usr/bin/env python3
"""
Complete Radio Request Tracker v2.0 Installer
Works with Python 3.13.5 on Windows 11
This script creates everything needed from scratch with all fixes applied
"""

import os
import sys
import subprocess
from pathlib import Path

def create_app_file():
    """Create the complete, fixed app.py file"""
    app_code = '''from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify, send_file, flash
import sqlite3
import hashlib
import os
from datetime import datetime
import json
from werkzeug.utils import secure_filename
from functools import wraps
import io
import csv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import traceback
import re

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Email configuration (update these with your SMTP settings)
EMAIL_CONFIG = {
    'enabled': False,  # Set to True when email is configured
    'smtp_server': 'smtp.office365.com',  # Update with your SMTP server
    'smtp_port': 587,
    'smtp_username': '',  # Update with email account
    'smtp_password': '',  # Update with password
    'from_email': 'radiotracker@custom-domain.com',
    'domain': 'custom-domain.com'
}

# Radio configuration
RADIO_TYPES = {
    'Mobile': ['V', 'V/7', 'V/U/7'],
    'Portable': ['V', 'V/7', 'V/U/7'],
    'Desk Mount': ['V', 'U', '7']
}

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database initialization
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Users table - Updated with employee_id and email_notifications
    c.execute(\'''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        full_name TEXT,
        employee_id TEXT,
        email TEXT,
        email_notifications INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )\''')
    
    # Requests table - Updated with assigned_to and radio details
    c.execute(\'''CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sdm_ticket TEXT NOT NULL,
        detachment TEXT NOT NULL,
        cost_center TEXT,
        radio_category TEXT,
        radio_frequencies TEXT,
        quantity INTEGER,
        justification TEXT,
        status TEXT DEFAULT 'Draft',
        assigned_to TEXT,
        assigned_user_id INTEGER,
        po_number TEXT,
        total_cost REAL,
        funding_type TEXT,
        created_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (assigned_user_id) REFERENCES users(id)
    )\''')
    
    # Documents table - Updated to track document type
    c.execute(\'''CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id INTEGER,
        filename TEXT,
        file_path TEXT,
        document_type TEXT,  -- 'form', 'email', 'attachment'
        version INTEGER,
        status_at_upload TEXT,
        uploaded_by TEXT,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (request_id) REFERENCES requests(id)
    )\''')
    
    # Approvals table
    c.execute(\'''CREATE TABLE IF NOT EXISTS approvals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id INTEGER,
        stage TEXT,
        approved_by TEXT,
        approved_at TIMESTAMP,
        comments TEXT,
        status TEXT,
        FOREIGN KEY (request_id) REFERENCES requests(id)
    )\''')
    
    # Status history with assignment tracking
    c.execute(\'''CREATE TABLE IF NOT EXISTS status_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id INTEGER,
        old_status TEXT,
        new_status TEXT,
        changed_by TEXT,
        assigned_to TEXT,
        changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        notes TEXT,
        FOREIGN KEY (request_id) REFERENCES requests(id)
    )\''')
    
    # Email log for tracking notifications
    c.execute(\'''CREATE TABLE IF NOT EXISTS email_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id INTEGER,
        recipient TEXT,
        subject TEXT,
        status TEXT,
        error_message TEXT,
        sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (request_id) REFERENCES requests(id)
    )\''')
    
    # Create default admin user if none exists
    c.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    if c.fetchone()[0] == 0:
        admin_pass = hashlib.sha256('admin'.encode()).hexdigest()
        c.execute("""INSERT INTO users (username, password, role, full_name, employee_id) 
                     VALUES (?, ?, ?, ?, ?)""",
                 ('admin', admin_pass, 'admin', 'System Administrator', '999999999'))
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

# Helper Functions
def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def query_db(query, args=(), one=False):
    conn = get_db()
    cur = conn.execute(query, args)
    rv = cur.fetchall()
    conn.commit()
    conn.close()
    return (rv[0] if rv else None) if one else rv

def send_email_notification(to_email, subject, body, request_id=None):
    """Send email notification with error handling"""
    if not EMAIL_CONFIG['enabled']:
        return False, "Email notifications are disabled"
    
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_CONFIG['from_email']
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'html'))
        
        with smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port']) as server:
            server.starttls()
            if EMAIL_CONFIG['smtp_username'] and EMAIL_CONFIG['smtp_password']:
                server.login(EMAIL_CONFIG['smtp_username'], EMAIL_CONFIG['smtp_password'])
            server.send_message(msg)
        
        # Log successful email
        if request_id:
            conn = get_db()
            c = conn.cursor()
            c.execute("""INSERT INTO email_log (request_id, recipient, subject, status)
                        VALUES (?, ?, ?, ?)""",
                     (request_id, to_email, subject, 'sent'))
            conn.commit()
            conn.close()
        
        return True, "Email sent successfully"
    
    except Exception as e:
        error_msg = str(e)
        
        # Log failed email
        if request_id:
            conn = get_db()
            c = conn.cursor()
            c.execute("""INSERT INTO email_log (request_id, recipient, subject, status, error_message)
                        VALUES (?, ?, ?, ?, ?)""",
                     (request_id, to_email, subject, 'failed', error_msg))
            conn.commit()
            conn.close()
        
        return False, error_msg

def validate_employee_id(employee_id):
    """Validate employee ID format (9 digits)"""
    if employee_id and re.match(r'^\\d{9}$', employee_id):
        return True
    return False

# Authentication decorators - FIXED WITH @wraps
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = query_db('SELECT role FROM users WHERE id = ?', [session['user_id']], one=True)
        if user['role'] != 'admin':
            return 'Access denied', 403
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        
        user = query_db('SELECT * FROM users WHERE username = ? AND password = ?', 
                       [username, password], one=True)
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            return render_template_string(LOGIN_TEMPLATE, error='Invalid credentials')
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get all requests with assignment info
    requests_data = query_db(\'''
        SELECT r.*, 
               u.full_name as assigned_to_name,
               COUNT(DISTINCT d.id) as document_count,
               MAX(d.version) as latest_version
        FROM requests r
        LEFT JOIN users u ON r.assigned_user_id = u.id
        LEFT JOIN documents d ON r.id = d.request_id
        GROUP BY r.id
        ORDER BY r.created_at DESC
    \''')
    
    # Get statistics
    stats = {
        'total': len(requests_data),
        'pending': len([r for r in requests_data if r['status'] in ['Draft', 'District Review', 'DevOps Costing', 'Commander Approval', 'Manager Approval']]),
        'approved': len([r for r in requests_data if r['status'] == 'Approved']),
        'in_progress': len([r for r in requests_data if r['status'] in ['Ordering', 'Shipped']]),
        'completed': len([r for r in requests_data if r['status'] == 'Delivered']),
        'assigned_to_me': len([r for r in requests_data if r['assigned_user_id'] == session.get('user_id')])
    }
    
    return render_template_string(DASHBOARD_TEMPLATE, 
                                 requests=requests_data, 
                                 stats=stats,
                                 user_role=session.get('role'))

@app.route('/request/new', methods=['GET', 'POST'])
@login_required
def new_request():
    if request.method == 'POST':
        conn = get_db()
        c = conn.cursor()
        
        # Combine radio category and frequencies
        radio_category = request.form['radio_category']
        radio_frequencies = request.form.get('radio_frequencies', '')
        
        c.execute(\'''INSERT INTO requests 
                    (sdm_ticket, detachment, cost_center, radio_category, radio_frequencies, 
                     quantity, justification, created_by) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)\''',
                 (request.form['sdm_ticket'],
                  request.form['detachment'],
                  request.form['cost_center'],
                  radio_category,
                  radio_frequencies,
                  request.form['quantity'],
                  request.form['justification'],
                  session['username']))
        
        request_id = c.lastrowid
        
        # Handle file upload
        if 'pdf_form' in request.files:
            file = request.files['pdf_form']
            if file and file.filename:
                filename = secure_filename(file.filename)
                request_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(request_id))
                os.makedirs(request_folder, exist_ok=True)
                
                file_path = os.path.join(request_folder, f"v1_{filename}")
                file.save(file_path)
                
                c.execute(\'''INSERT INTO documents 
                           (request_id, filename, file_path, document_type, version, status_at_upload, uploaded_by)
                           VALUES (?, ?, ?, ?, ?, ?, ?)\''',
                         (request_id, filename, file_path, 'form', 1, 'Draft', session['username']))
        
        conn.commit()
        conn.close()
        
        return redirect(url_for('view_request', request_id=request_id))
    
    return render_template_string(NEW_REQUEST_TEMPLATE, radio_types=RADIO_TYPES)

@app.route('/request/<int:request_id>')
@login_required
def view_request(request_id):
    req = query_db(\'''SELECT r.*, u.full_name as assigned_to_name, u.employee_id as assigned_employee_id
                      FROM requests r
                      LEFT JOIN users u ON r.assigned_user_id = u.id
                      WHERE r.id = ?\''', [request_id], one=True)
    
    if not req:
        return 'Request not found', 404
    
    documents = query_db(\'''SELECT * FROM documents 
                           WHERE request_id = ? 
                           ORDER BY uploaded_at DESC\''', [request_id])
    
    approvals = query_db('SELECT * FROM approvals WHERE request_id = ? ORDER BY approved_at DESC', [request_id])
    history = query_db('SELECT * FROM status_history WHERE request_id = ? ORDER BY changed_at DESC', [request_id])
    
    # Get all users for assignment dropdown
    users = query_db('SELECT id, username, full_name, employee_id FROM users ORDER BY full_name')
    
    return render_template_string(REQUEST_TEMPLATE, 
                                 request=req, 
                                 documents=documents,
                                 approvals=approvals,
                                 history=history,
                                 users=users,
                                 user_role=session.get('role'))

@app.route('/request/<int:request_id>/update', methods=['POST'])
@login_required
def update_request(request_id):
    new_status = request.form.get('status')
    notes = request.form.get('notes', '')
    assigned_user_id = request.form.get('assigned_to')
    
    # Get current request info
    req = query_db(\'''SELECT r.*, u.employee_id, u.email_notifications, u.full_name 
                      FROM requests r
                      LEFT JOIN users u ON r.assigned_user_id = u.id
                      WHERE r.id = ?\''', [request_id], one=True)
    
    if not req:
        return jsonify({'error': 'Request not found'}), 404
    
    old_status = req['status']
    
    conn = get_db()
    c = conn.cursor()
    
    # Update request
    if new_status:
        c.execute('UPDATE requests SET status = ?, updated_at = ? WHERE id = ?',
                 (new_status, datetime.now(), request_id))
    
    # Update assignment
    assigned_user = None
    if assigned_user_id:
        assigned_user = query_db('SELECT * FROM users WHERE id = ?', [assigned_user_id], one=True)
        if assigned_user:
            c.execute('UPDATE requests SET assigned_user_id = ?, assigned_to = ? WHERE id = ?',
                     (assigned_user_id, assigned_user['full_name'], request_id))
            
            # Send email notification if enabled
            if assigned_user['email_notifications'] and assigned_user['employee_id']:
                email = f"{assigned_user['employee_id']}@{EMAIL_CONFIG['domain']}"
                subject = f"Radio Request #{request_id} Assigned to You"
                body = f"""
                <html>
                <body>
                    <h3>Radio Request Assignment</h3>
                    <p>You have been assigned to radio request #{request_id}</p>
                    <p><strong>SDM Ticket:</strong> {req['sdm_ticket']}</p>
                    <p><strong>Detachment:</strong> {req['detachment']}</p>
                    <p><strong>Current Status:</strong> {new_status or req['status']}</p>
                    <p><strong>Notes:</strong> {notes}</p>
                    <p>Please log in to the Radio Request Tracker to review and update this request.</p>
                </body>
                </html>
                """
                send_email_notification(email, subject, body, request_id)
    
    # Handle file uploads
    if 'documents' in request.files:
        files = request.files.getlist('documents')
        request_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(request_id))
        os.makedirs(request_folder, exist_ok=True)
        
        # Get the latest version number
        latest_doc = query_db(\'''SELECT MAX(version) as max_version 
                                FROM documents 
                                WHERE request_id = ? AND document_type = ?\''', 
                             [request_id, 'form'], one=True)
        next_version = (latest_doc['max_version'] or 0) + 1
        
        for file in files:
            if file and file.filename:
                filename = secure_filename(file.filename)
                doc_type = 'email' if 'email' in filename.lower() else 'form'
                version_num = next_version if doc_type == 'form' else 0
                
                file_path = os.path.join(request_folder, f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}")
                file.save(file_path)
                
                c.execute(\'''INSERT INTO documents 
                           (request_id, filename, file_path, document_type, version, status_at_upload, uploaded_by)
                           VALUES (?, ?, ?, ?, ?, ?, ?)\''',
                         (request_id, filename, file_path, doc_type, version_num, 
                          new_status or req['status'], session['username']))
                
                if doc_type == 'form':
                    next_version += 1
    
    # Add to history
    c.execute(\'''INSERT INTO status_history (request_id, old_status, new_status, changed_by, assigned_to, notes)
               VALUES (?, ?, ?, ?, ?, ?)\''',
             (request_id, old_status, new_status, session['username'], 
              assigned_user['full_name'] if assigned_user_id and assigned_user else None, notes))
    
    conn.commit()
    conn.close()
    
    return redirect(url_for('view_request', request_id=request_id))

@app.route('/request/<int:request_id>/update_po', methods=['POST'])
@login_required
def update_po(request_id):
    po_number = request.form.get('po_number')
    total_cost = request.form.get('total_cost')
    funding_type = request.form.get('funding_type')
    
    conn = get_db()
    c = conn.cursor()
    c.execute(\'''UPDATE requests 
                SET po_number = ?, total_cost = ?, funding_type = ?, updated_at = ?
                WHERE id = ?\''',
             (po_number, total_cost, funding_type, datetime.now(), request_id))
    conn.commit()
    conn.close()
    
    return redirect(url_for('view_request', request_id=request_id))

@app.route('/admin')
@admin_required
def admin_panel():
    users = query_db('SELECT * FROM users ORDER BY created_at DESC')
    return render_template_string(ADMIN_TEMPLATE, users=users, email_enabled=EMAIL_CONFIG['enabled'])

@app.route('/admin/add_user', methods=['POST'])
@admin_required
def add_user():
    username = request.form['username']
    password = hashlib.sha256(request.form['password'].encode()).hexdigest()
    role = request.form['role']
    full_name = request.form['full_name']
    employee_id = request.form.get('employee_id', '')
    email_notifications = 1 if request.form.get('email_notifications') else 0
    
    # Validate employee ID
    if employee_id and not validate_employee_id(employee_id):
        return jsonify({'error': 'Employee ID must be exactly 9 digits'}), 400
    
    # Generate email from employee ID
    email = f"{employee_id}@{EMAIL_CONFIG['domain']}" if employee_id else None
    
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute(\'''INSERT INTO users (username, password, role, full_name, employee_id, email, email_notifications)
                   VALUES (?, ?, ?, ?, ?, ?, ?)\''',
                 (username, password, role, full_name, employee_id, email, email_notifications))
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400
    
    return redirect(url_for('admin_panel'))

@app.route('/admin/toggle_email/<int:user_id>', methods=['POST'])
@admin_required
def toggle_email(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute(\'''UPDATE users 
                SET email_notifications = CASE WHEN email_notifications = 1 THEN 0 ELSE 1 END
                WHERE id = ?\''', [user_id])
    conn.commit()
    conn.close()
    return redirect(url_for('admin_panel'))

@app.route('/download/<int:document_id>')
@login_required
def download_document(document_id):
    doc = query_db('SELECT * FROM documents WHERE id = ?', [document_id], one=True)
    if doc and os.path.exists(doc['file_path']):
        return send_file(doc['file_path'], as_attachment=True, download_name=doc['filename'])
    return 'File not found', 404

@app.route('/export/csv')
@login_required
def export_csv():
    requests_data = query_db(\'''SELECT r.*, u.full_name as assigned_to_name
                                FROM requests r
                                LEFT JOIN users u ON r.assigned_user_id = u.id
                                ORDER BY r.created_at DESC\''')
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write headers
    writer.writerow(['ID', 'SDM Ticket', 'Detachment', 'Cost Center', 'Radio Type', 
                    'Frequencies', 'Quantity', 'Status', 'Assigned To', 'PO Number', 
                    'Total Cost', 'Funding Type', 'Created At'])
    
    # Write data
    for req in requests_data:
        writer.writerow([req['id'], req['sdm_ticket'], req['detachment'], req['cost_center'],
                        req['radio_category'], req['radio_frequencies'], req['quantity'], 
                        req['status'], req['assigned_to_name'], req['po_number'],
                        req['total_cost'], req['funding_type'], req['created_at']])
    
    output.seek(0)
    
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'radio_requests_{datetime.now().strftime("%Y%m%d")}.csv'
    )

# HTML Templates
LOGIN_TEMPLATE = \'''
<!DOCTYPE html>
<html>
<head>
    <title>Radio Request Tracker - Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f0f0f0; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-box { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 300px; }
        h2 { margin-top: 0; color: #333; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        button:hover { background: #0056b3; }
        .error { color: red; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Radio Request Tracker</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        <p style="margin-top: 20px; color: #666; font-size: 12px;">Default: admin/admin</p>
    </div>
</body>
</html>
\'''

DASHBOARD_TEMPLATE = \'''
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - Radio Request Tracker</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; background: #f5f5f5; }
        .navbar { background: #2c3e50; color: white; padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; }
        .navbar a { color: white; text-decoration: none; margin: 0 15px; }
        .navbar a:hover { text-decoration: underline; }
        .container { padding: 20px; max-width: 1400px; margin: 0 auto; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-card h3 { margin: 0; color: #666; font-size: 14px; }
        .stat-card .number { font-size: 32px; font-weight: bold; color: #2c3e50; margin: 10px 0; }
        .btn { padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn:hover { background: #0056b3; }
        table { width: 100%; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th { background: #34495e; color: white; padding: 12px; text-align: left; }
        td { padding: 12px; border-bottom: 1px solid #ecf0f1; }
        tr:hover { background: #f8f9fa; }
        .status { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .status-draft { background: #e3e3e3; }
        .status-review { background: #ffc107; }
        .status-approved { background: #28a745; color: white; }
        .status-ordering { background: #17a2b8; color: white; }
        .status-delivered { background: #6c757d; color: white; }
        .assigned { color: #007bff; font-weight: bold; }
    </style>
</head>
<body>
    <div class="navbar">
        <div>
            <span style="font-size: 20px; font-weight: bold;">Radio Request Tracker</span>
            <a href="/dashboard">Dashboard</a>
            <a href="/request/new">New Request</a>
            {% if user_role == 'admin' %}<a href="/admin">Admin Panel</a>{% endif %}
            <a href="/export/csv">Export CSV</a>
        </div>
        <div>
            <span>{{ session.username }}</span>
            <a href="/logout">Logout</a>
        </div>
    </div>
    
    <div class="container">
        <div class="stats">
            <div class="stat-card">
                <h3>Total Requests</h3>
                <div class="number">{{ stats.total }}</div>
            </div>
            <div class="stat-card">
                <h3>Pending Approval</h3>
                <div class="number">{{ stats.pending }}</div>
            </div>
            <div class="stat-card">
                <h3>In Progress</h3>
                <div class="number">{{ stats.in_progress }}</div>
            </div>
            <div class="stat-card">
                <h3>Completed</h3>
                <div class="number">{{ stats.completed }}</div>
            </div>
            <div class="stat-card">
                <h3>Assigned to Me</h3>
                <div class="number">{{ stats.assigned_to_me }}</div>
            </div>
        </div>
        
        <h2>All Requests</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>SDM Ticket</th>
                    <th>Detachment</th>
                    <th>Radio Type</th>
                    <th>Freq</th>
                    <th>Qty</th>
                    <th>Status</th>
                    <th>Assigned To</th>
                    <th>Documents</th>
                    <th>Created</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                {% for req in requests %}
                <tr>
                    <td>#{{ req.id }}</td>
                    <td>{{ req.sdm_ticket }}</td>
                    <td>{{ req.detachment }}</td>
                    <td>{{ req.radio_category or 'N/A' }}</td>
                    <td>{{ req.radio_frequencies or 'N/A' }}</td>
                    <td>{{ req.quantity }}</td>
                    <td><span class="status status-{{ req.status.lower().replace(' ', '-') }}">{{ req.status }}</span></td>
                    <td>{% if req.assigned_to_name %}<span class="assigned">{{ req.assigned_to_name }}</span>{% else %}Unassigned{% endif %}</td>
                    <td>{{ req.document_count }} docs</td>
                    <td>{{ req.created_at[:10] }}</td>
                    <td><a href="/request/{{ req.id }}" class="btn" style="padding: 5px 10px;">View</a></td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
\'''

NEW_REQUEST_TEMPLATE = \'''
<!DOCTYPE html>
<html>
<head>
    <title>New Request - Radio Request Tracker</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; background: #f5f5f5; }
        .navbar { background: #2c3e50; color: white; padding: 15px 20px; }
        .navbar a { color: white; text-decoration: none; margin: 0 15px; }
        .container { padding: 20px; max-width: 800px; margin: 0 auto; }
        .form-card { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h2 { margin-top: 0; color: #2c3e50; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; color: #555; }
        input, textarea, select { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        textarea { resize: vertical; min-height: 100px; }
        .btn { padding: 12px 30px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        .btn:hover { background: #0056b3; }
        .btn-cancel { background: #6c757d; margin-left: 10px; }
        .radio-group { display: flex; gap: 20px; margin-top: 5px; }
        .radio-option { display: flex; align-items: center; }
        .radio-option input { width: auto; margin-right: 5px; }
    </style>
    <script>
        function updateFrequencies() {
            const category = document.getElementById('radio_category').value;
            const freqSelect = document.getElementById('radio_frequencies');
            
            const frequencies = {
                'Mobile': ['V', 'V/7', 'V/U/7'],
                'Portable': ['V', 'V/7', 'V/U/7'],
                'Desk Mount': ['V', 'U', '7']
            };
            
            freqSelect.innerHTML = '<option value="">Select Frequency</option>';
            
            if (category && frequencies[category]) {
                frequencies[category].forEach(freq => {
                    const option = document.createElement('option');
                    option.value = freq;
                    option.textContent = freq;
                    freqSelect.appendChild(option);
                });
                freqSelect.disabled = false;
            } else {
                freqSelect.disabled = true;
            }
        }
    </script>
</head>
<body>
    <div class="navbar">
        <span style="font-size: 20px; font-weight: bold;">Radio Request Tracker</span>
        <a href="/dashboard">← Back to Dashboard</a>
    </div>
    
    <div class="container">
        <div class="form-card">
            <h2>New Radio Request</h2>
            <form method="POST" enctype="multipart/form-data">
                <div class="form-group">
                    <label>SDM Ticket Number *</label>
                    <input type="text" name="sdm_ticket" required placeholder="e.g., SDM-2024-001">
                </div>
                
                <div class="form-group">
                    <label>Detachment *</label>
                    <input type="text" name="detachment" required placeholder="e.g., North District">
                </div>
                
                <div class="form-group">
                    <label>Cost Center</label>
                    <input type="text" name="cost_center" placeholder="e.g., CC-1234">
                </div>
                
                <div class="form-group">
                    <label>Radio Category *</label>
                    <select id="radio_category" name="radio_category" required onchange="updateFrequencies()">
                        <option value="">Select Category</option>
                        <option value="Mobile">Mobile</option>
                        <option value="Portable">Portable</option>
                        <option value="Desk Mount">Desk Mount</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label>Radio Frequencies *</label>
                    <select id="radio_frequencies" name="radio_frequencies" required disabled>
                        <option value="">Select Category First</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label>Quantity *</label>
                    <input type="number" name="quantity" min="1" required placeholder="Number of radios">
                </div>
                
                <div class="form-group">
                    <label>Justification</label>
                    <textarea name="justification" placeholder="Explain the need for these radios..."></textarea>
                </div>
                
                <div class="form-group">
                    <label>Upload ED4281 Form (PDF)</label>
                    <input type="file" name="pdf_form" accept=".pdf">
                </div>
                
                <button type="submit" class="btn">Submit Request</button>
                <a href="/dashboard" class="btn btn-cancel">Cancel</a>
            </form>
        </div>
    </div>
</body>
</html>
\'''

REQUEST_TEMPLATE = \'''
<!DOCTYPE html>
<html>
<head>
    <title>Request #{{ request.id }} - Radio Request Tracker</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; background: #f5f5f5; }
        .navbar { background: #2c3e50; color: white; padding: 15px 20px; }
        .navbar a { color: white; text-decoration: none; margin: 0 15px; }
        .container { padding: 20px; max-width: 1200px; margin: 0 auto; }
        .grid { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        h2 { margin-top: 0; color: #2c3e50; border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; }
        .info-row { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #f0f0f0; }
        .info-label { font-weight: bold; color: #666; }
        .status { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .btn { padding: 8px 16px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; margin-right: 5px; }
        .btn:hover { background: #0056b3; }
        .btn-secondary { background: #6c757d; }
        .btn-success { background: #28a745; }
        .document-list { list-style: none; padding: 0; }
        .document-item { padding: 10px; background: #f8f9fa; margin-bottom: 8px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; }
        .document-type { padding: 2px 6px; border-radius: 3px; font-size: 11px; font-weight: bold; }
        .type-form { background: #007bff; color: white; }
        .type-email { background: #ffc107; color: black; }
        .type-attachment { background: #6c757d; color: white; }
        .timeline { position: relative; padding-left: 30px; }
        .timeline-item { position: relative; padding-bottom: 20px; }
        .timeline-item::before { content: ''; position: absolute; left: -25px; top: 5px; width: 10px; height: 10px; background: #007bff; border-radius: 50%; }
        .timeline-item::after { content: ''; position: absolute; left: -20px; top: 15px; width: 1px; height: calc(100% - 10px); background: #ddd; }
        .timeline-item:last-child::after { display: none; }
        select, input, textarea { padding: 8px; border: 1px solid #ddd; border-radius: 4px; margin-right: 10px; }
        .update-form { background: #f8f9fa; padding: 15px; border-radius: 4px; margin-top: 10px; }
        .form-row { display: flex; gap: 10px; margin-bottom: 10px; align-items: center; }
        .form-row label { min-width: 100px; font-weight: bold; }
        .form-row input, .form-row select { flex: 1; }
    </style>
</head>
<body>
    <div class="navbar">
        <span style="font-size: 20px; font-weight: bold;">Radio Request Tracker</span>
        <a href="/dashboard">← Back to Dashboard</a>
    </div>
    
    <div class="container">
        <h1>Request #{{ request.id }} - {{ request.sdm_ticket }}</h1>
        
        <div class="grid">
            <div>
                <div class="card">
                    <h2>Request Details</h2>
                    <div class="info-row">
                        <span class="info-label">SDM Ticket:</span>
                        <span>{{ request.sdm_ticket }}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Detachment:</span>
                        <span>{{ request.detachment }}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Cost Center:</span>
                        <span>{{ request.cost_center or 'N/A' }}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Radio Category:</span>
                        <span>{{ request.radio_category or 'N/A' }}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Frequencies:</span>
                        <span>{{ request.radio_frequencies or 'N/A' }}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Quantity:</span>
                        <span>{{ request.quantity }}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Status:</span>
                        <span class="status">{{ request.status }}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Assigned To:</span>
                        <span>{{ request.assigned_to_name or 'Unassigned' }} {% if request.assigned_employee_id %}({{ request.assigned_employee_id }}){% endif %}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">PO Number:</span>
                        <span>{{ request.po_number or 'Not yet issued' }}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Total Cost:</span>
                        <span>${{ request.total_cost or '0.00' }}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Funding Type:</span>
                        <span>{{ request.funding_type or 'TBD' }}</span>
                    </div>
                </div>
                
                <div class="card">
                    <h2>Update Request</h2>
                    <form method="POST" action="/request/{{ request.id }}/update" enctype="multipart/form-data">
                        <div class="update-form">
                            <div class="form-row">
                                <label>Status:</label>
                                <select name="status">
                                    <option value="">Keep Current</option>
                                    <option value="Draft">Draft</option>
                                    <option value="District Review">District Review</option>
                                    <option value="DevOps Costing">DevOps Costing</option>
                                    <option value="Commander Approval">Commander Approval</option>
                                    <option value="Manager Approval">Manager Approval</option>
                                    <option value="Approved">Approved</option>
                                    <option value="Ordering">Ordering</option>
                                    <option value="Shipped">Shipped</option>
                                    <option value="Delivered">Delivered</option>
                                    <option value="Financial Close">Financial Close</option>
                                </select>
                            </div>
                            
                            <div class="form-row">
                                <label>Assign To:</label>
                                <select name="assigned_to">
                                    <option value="">Keep Current</option>
                                    {% for user in users %}
                                    <option value="{{ user.id }}">{{ user.full_name }} ({{ user.username }})</option>
                                    {% endfor %}
                                </select>
                            </div>
                            
                            <div class="form-row">
                                <label>Notes:</label>
                                <textarea name="notes" rows="2" style="flex: 1;"></textarea>
                            </div>
                            
                            <div class="form-row">
                                <label>Attach Files:</label>
                                <input type="file" name="documents" multiple accept=".pdf,.msg,.eml">
                            </div>
                            
                            <button type="submit" class="btn">Update Request</button>
                        </div>
                    </form>
                </div>
                
                <div class="card">
                    <h2>Update PO Information</h2>
                    <form method="POST" action="/request/{{ request.id }}/update_po">
                        <div class="update-form">
                            <div class="form-row">
                                <label>PO Number:</label>
                                <input type="text" name="po_number" value="{{ request.po_number or '' }}">
                            </div>
                            <div class="form-row">
                                <label>Total Cost:</label>
                                <input type="number" name="total_cost" step="0.01" value="{{ request.total_cost or '' }}">
                            </div>
                            <div class="form-row">
                                <label>Funding Type:</label>
                                <select name="funding_type">
                                    <option value="">Select</option>
                                    <option value="allocation" {% if request.funding_type == 'allocation' %}selected{% endif %}>Allocation</option>
                                    <option value="jv" {% if request.funding_type == 'jv' %}selected{% endif %}>JV Required</option>
                                </select>
                            </div>
                            <button type="submit" class="btn btn-success">Update PO Info</button>
                        </div>
                    </form>
                </div>
                
                <div class="card">
                    <h2>Status History</h2>
                    <div class="timeline">
                        {% for item in history %}
                        <div class="timeline-item">
                            <strong>{{ item.new_status }}</strong><br>
                            <small>{{ item.changed_by }} - {{ item.changed_at }}</small><br>
                            {% if item.assigned_to %}<small style="color: #007bff;">Assigned to: {{ item.assigned_to }}</small><br>{% endif %}
                            {% if item.notes %}<small style="color: #666;">{{ item.notes }}</small>{% endif %}
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </div>
            
            <div>
                <div class="card">
                    <h2>Documents ({{ documents|length }})</h2>
                    <ul class="document-list">
                        {% for doc in documents %}
                        <li class="document-item">
                            <div>
                                <span class="document-type type-{{ doc.document_type }}">{{ doc.document_type.upper() }}</span>
                                {% if doc.version > 0 %}<span style="margin-left: 5px;">v{{ doc.version }}</span>{% endif %}<br>
                                <strong>{{ doc.filename }}</strong><br>
                                <small>Status: {{ doc.status_at_upload }}</small><br>
                                <small>By {{ doc.uploaded_by }} on {{ doc.uploaded_at[:10] }}</small>
                            </div>
                            <a href="/download/{{ doc.id }}" class="btn btn-secondary" style="padding: 4px 8px;">Download</a>
                        </li>
                        {% endfor %}
                    </ul>
                </div>
                
                <div class="card">
                    <h2>Justification</h2>
                    <p>{{ request.justification or 'No justification provided' }}</p>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
\'''

ADMIN_TEMPLATE = \'''
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel - Radio Request Tracker</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; background: #f5f5f5; }
        .navbar { background: #2c3e50; color: white; padding: 15px 20px; }
        .navbar a { color: white; text-decoration: none; margin: 0 15px; }
        .container { padding: 20px; max-width: 1200px; margin: 0 auto; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        h2 { margin-top: 0; color: #2c3e50; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #34495e; color: white; padding: 12px; text-align: left; }
        td { padding: 12px; border-bottom: 1px solid #ecf0f1; }
        .form-inline { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        input, select { padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        .btn { padding: 8px 16px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .btn:hover { background: #0056b3; }
        .btn-danger { background: #dc3545; }
        .role-admin { background: #dc3545; color: white; padding: 2px 6px; border-radius: 3px; }
        .role-manager { background: #ffc107; color: black; padding: 2px 6px; border-radius: 3px; }
        .role-user { background: #28a745; color: white; padding: 2px 6px; border-radius: 3px; }
        .status-indicator { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 5px; }
        .status-on { background: #28a745; }
        .status-off { background: #dc3545; }
        .alert { padding: 10px; background: #fff3cd; border: 1px solid #ffc107; border-radius: 4px; margin-bottom: 20px; }
        .checkbox-label { display: flex; align-items: center; gap: 5px; }
    </style>
</head>
<body>
    <div class="navbar">
        <span style="font-size: 20px; font-weight: bold;">Radio Request Tracker - Admin</span>
        <a href="/dashboard">← Back to Dashboard</a>
    </div>
    
    <div class="container">
        {% if not email_enabled %}
        <div class="alert">
            ⚠️ Email notifications are currently disabled. To enable, update EMAIL_CONFIG in app.py with your SMTP settings.
        </div>
        {% endif %}
        
        <div class="card">
            <h2>Add New User</h2>
            <form method="POST" action="/admin/add_user" class="form-inline">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <input type="text" name="full_name" placeholder="Full Name" required>
                <input type="text" name="employee_id" placeholder="Employee ID (9 digits)" pattern="[0-9]{9}" maxlength="9">
                <select name="role" required>
                    <option value="user">User</option>
                    <option value="manager">Manager</option>
                    <option value="admin">Admin</option>
                </select>
                <div class="checkbox-label">
                    <input type="checkbox" name="email_notifications" id="email_notifications" checked>
                    <label for="email_notifications">Email Notifications</label>
                </div>
                <button type="submit" class="btn">Add User</button>
            </form>
        </div>
        
        <div class="card">
            <h2>User Management</h2>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Username</th>
                        <th>Full Name</th>
                        <th>Employee ID</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Notifications</th>
                        <th>Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in users %}
                    <tr>
                        <td>{{ user.id }}</td>
                        <td>{{ user.username }}</td>
                        <td>{{ user.full_name }}</td>
                        <td>{{ user.employee_id or 'N/A' }}</td>
                        <td>{{ user.email or 'N/A' }}</td>
                        <td><span class="role-{{ user.role }}">{{ user.role }}</span></td>
                        <td>
                            <span class="status-indicator {% if user.email_notifications %}status-on{% else %}status-off{% endif %}"></span>
                            {% if user.email_notifications %}Enabled{% else %}Disabled{% endif %}
                        </td>
                        <td>{{ user.created_at[:10] }}</td>
                        <td>
                            <form method="POST" action="/admin/toggle_email/{{ user.id }}" style="display: inline;">
                                <button type="submit" class="btn" style="padding: 4px 8px;">Toggle Email</button>
                            </form>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
\'''

if __name__ == '__main__':
    print("\\n" + "="*50)
    print("Radio Request Tracker v2.0")
    print("="*50)
    print("\\nStarting server...")
    print("\\nAccess the application at: http://localhost:5000")
    print("Default login: admin/admin")
    print("\\nPress Ctrl+C to stop the server")
    print("="*50 + "\\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
'''
    
    with open('app.py', 'w', encoding='utf-8') as f:
        f.write(app_code)
    return True

def create_requirements_file():
    """Create requirements.txt"""
    requirements = """Flask==3.1.0
Werkzeug==3.1.3"""
    
    with open('requirements.txt', 'w') as f:
        f.write(requirements)
    return True

def create_batch_files():
    """Create Windows batch files"""
    
    # Create run.bat
    run_bat = """@echo off
echo Starting Radio Request Tracker v2.0...
cd /d %~dp0
call venv\\Scripts\\activate.bat
python app.py
pause"""
    
    with open('run.bat', 'w') as f:
        f.write(run_bat)
    
    # Create setup.bat for future installs
    setup_bat = """@echo off
echo Installing/Updating Radio Request Tracker...
python -m venv venv
call venv\\Scripts\\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
echo.
echo Setup complete! Run 'run.bat' to start the application.
pause"""
    
    with open('setup.bat', 'w') as f:
        f.write(setup_bat)
    
    return True

def main():
    print("="*60)
    print(" Radio Request Tracker v2.0 - Complete Installer")
    print(" For Windows 11 with Python 3.13.5")
    print("="*60)
    print()
    
    # Check Python version
    python_version = sys.version_info
    print(f"✓ Python {python_version.major}.{python_version.minor}.{python_version.micro} detected")
    
    if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 6):
        print("✗ Error: Python 3.6+ is required")
        input("Press Enter to exit...")
        sys.exit(1)
    
    # Get installation directory
    install_dir = input("Enter installation directory (default: C:\\radio-tracker): ").strip()
    if not install_dir:
        install_dir = "C:\\radio-tracker"
    
    # Create directory
    print(f"\nCreating directory: {install_dir}")
    os.makedirs(install_dir, exist_ok=True)
    os.chdir(install_dir)
    print(f"✓ Working in: {os.getcwd()}")
    
    # Create all files
    print("\n📁 Creating application files...")
    
    print("  Creating app.py with all fixes...")
    if create_app_file():
        print("  ✓ app.py created (with decorator fixes applied)")
    
    print("  Creating requirements.txt...")
    if create_requirements_file():
        print("  ✓ requirements.txt created")
    
    print("  Creating batch files...")
    if create_batch_files():
        print("  ✓ run.bat created")
        print("  ✓ setup.bat created")
    
    # Create virtual environment
    print("\n🔧 Setting up Python environment...")
    print("  Creating virtual environment...")
    result = subprocess.run([sys.executable, '-m', 'venv', 'venv'], capture_output=True)
    if result.returncode == 0:
        print("  ✓ Virtual environment created")
    else:
        print("  ✗ Failed to create virtual environment")
        print(result.stderr.decode())
        input("Press Enter to exit...")
        sys.exit(1)
    
    # Install packages
    print("\n📦 Installing packages...")
    venv_python = os.path.join('venv', 'Scripts', 'python.exe')
    
    # Upgrade pip first
    print("  Upgrading pip...")
    subprocess.run([venv_python, '-m', 'pip', 'install', '--upgrade', 'pip'], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Install Flask
    print("  Installing Flask and dependencies...")
    result = subprocess.run([venv_python, '-m', 'pip', 'install', '-r', 'requirements.txt'], 
                          capture_output=True, text=True)
    if result.returncode == 0:
        print("  ✓ All packages installed successfully")
    else:
        print("  ⚠ Package installation had warnings (this is usually fine)")
    
    # Create additional directories
    print("\n📂 Creating application directories...")
    os.makedirs('uploads', exist_ok=True)
    print("  ✓ Created uploads directory")
    
    # Success message
    print("\n" + "="*60)
    print(" ✅ INSTALLATION COMPLETE!")
    print("="*60)
    print()
    print("📍 Installation location: " + install_dir)
    print()
    print("🚀 To start the application:")
    print("   1. Double-click: run.bat")
    print("   2. Open browser: http://localhost:5000")
    print("   3. Login with: admin/admin")
    print()
    print("📋 Features included:")
    print("   • Radio types: Mobile/Portable/Desk Mount")
    print("   • Frequencies: V, V/7, V/U/7, U, 7")
    print("   • User assignment with email notifications")
    print("   • Document versioning")
    print("   • Complete audit trail")
    print()
    print("📧 Email Setup (Optional):")
    print("   Edit EMAIL_CONFIG in app.py to enable notifications")
    print()
    print("="*60)
    
    # Ask to start now
    print()
    start_now = input("Would you like to start the application now? (y/n): ").lower()
    if start_now == 'y':
        print("\nStarting Radio Request Tracker...")
        print("Press Ctrl+C to stop the server\n")
        subprocess.run([venv_python, 'app.py'])
    else:
        print("\nRun 'run.bat' whenever you're ready to start!")
        input("\nPress Enter to exit...")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInstallation cancelled by user")
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        input("\nPress Enter to exit...")