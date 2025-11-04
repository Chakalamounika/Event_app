from flask import Flask, render_template, request, redirect, url_for, flash, session
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = "supersecret"

DB_CONFIG = {
    "host": "127.0.0.1",
    "user": "ems_user",
    "password": "ems_pass",
    "database": "ems_db",
    "port": 3307
}

def get_db():
    return mysql.connector.connect(**DB_CONFIG)

# Template filter for formatting datetimes
@app.template_filter('display_dt')
def display_dt(value):
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M")
    try:
        # DB sometimes returns string; cut to minute resolution
        s = str(value)
        return s[:16]
    except:
        return value

def parse_dt_local(dt_str):
    """Convert HTML datetime-local 'YYYY-MM-DDTHH:MM' to Python datetime or string usable by MySQL connector"""
    if not dt_str:
        return None
    # return Python datetime; mysql-connector will accept datetime objects
    return datetime.strptime(dt_str, "%Y-%m-%dT%H:%M")

def init_db():
    """Create DB + tables + default admin + one sample event (if empty)."""
    conn = mysql.connector.connect(
        host=DB_CONFIG['host'],
        user=DB_CONFIG['user'],
        password=DB_CONFIG['password'],
        port=DB_CONFIG['port']
    )
    cursor = conn.cursor()
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']}")
    conn.database = DB_CONFIG['database']

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100),
        email VARCHAR(100) UNIQUE,
        password_hash VARCHAR(255),
        is_admin TINYINT DEFAULT 0
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255),
        description TEXT,
        location VARCHAR(255),
        start_datetime DATETIME,
        end_datetime DATETIME,
        capacity INT,
        approved TINYINT DEFAULT 0
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS registrations (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        event_id INT,
        UNIQUE(user_id, event_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
    )
    """)

    # default admin
    cursor.execute("SELECT id FROM users WHERE email=%s", ("admin@example.com",))
    if cursor.fetchone() is None:
        cursor.execute(
            "INSERT INTO users (name,email,password_hash,is_admin) VALUES (%s,%s,%s,%s)",
            ("Admin", "admin@example.com", generate_password_hash("admin123"), 1)
        )

    # sample event if none exists (approved)
    cursor.execute("SELECT id FROM events LIMIT 1")
    if cursor.fetchone() is None:
        now = datetime.now()
        start = now.strftime("%Y-%m-%d %H:%M:%S")
        end = (now.replace(hour=(now.hour + 2) % 24)).strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT INTO events (title,description,location,start_datetime,end_datetime,capacity,approved)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, ("Sample Event", "This is a sample event description.", "Conference Hall A", start, end, 100, 1))

    conn.commit()
    cursor.close()
    conn.close()

# ---------- ROUTES ----------
@app.route('/')
def index():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM events WHERE approved=1 ORDER BY start_datetime")
    events = cursor.fetchall()
    cursor.close(); conn.close()
    return render_template('main.html', page='index', events=events)

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip().lower()
        password_hash = generate_password_hash(request.form['password'])
        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (name,email,password_hash) VALUES (%s,%s,%s)",
                           (name, email, password_hash))
            conn.commit()
            flash("Registered successfully. Please log in.")
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            flash("Email already exists.")
        finally:
            cursor.close(); conn.close()
    return render_template('main.html', page='register')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close(); conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['is_admin'] = bool(user['is_admin'])
            flash("Login successful.")
            # If admin, send to dashboard
            if session['is_admin']:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('index'))
        flash("Invalid credentials.")
    return render_template('main.html', page='login')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for('index'))

@app.route('/event/<int:event_id>', methods=['GET','POST'])
def event_detail(event_id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM events WHERE id=%s", (event_id,))
    event = cursor.fetchone()

    user_registered = False
    if 'user_id' in session:
        cursor.execute("SELECT 1 FROM registrations WHERE user_id=%s AND event_id=%s",
                       (session['user_id'], event_id))
        user_registered = cursor.fetchone() is not None

    if request.method == 'POST':
        if 'user_id' not in session:
            flash("Login to register.")
            cursor.close(); conn.close()
            return redirect(url_for('login'))
        if not user_registered:
            cursor.execute("INSERT INTO registrations (user_id,event_id) VALUES (%s,%s)",
                           (session['user_id'], event_id))
            conn.commit()
            flash("Registered for event.")
            user_registered = True
        else:
            flash("You already registered for this event.")

    cursor.close(); conn.close()
    return render_template('main.html', page='event_detail', event=event, user_registered=user_registered)

@app.route('/my_registrations')
def my_registrations():
    if 'user_id' not in session:
        flash("Login to view registrations.")
        return redirect(url_for('login'))
    if session.get('is_admin'):
        # admins use admin dashboard instead
        return redirect(url_for('admin_dashboard'))

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT e.* FROM events e
        JOIN registrations r ON e.id = r.event_id
        WHERE r.user_id = %s
        ORDER BY e.start_datetime
    """, (session['user_id'],))
    regs = cursor.fetchall()
    cursor.close(); conn.close()
    return render_template('main.html', page='my_registrations', registrations=regs)

# ---------- ADMIN ----------
@app.route('/admin')
def admin_dashboard():
    if not session.get('is_admin'):
        flash("Admin only.")
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT e.*,
            (SELECT COUNT(*) FROM registrations r WHERE r.event_id = e.id) AS registered_count
        FROM events e
        ORDER BY e.start_datetime
    """)
    events = cursor.fetchall()
    cursor.close(); conn.close()
    return render_template('main.html', page='admin_dashboard', events=events)

@app.route('/admin/event', methods=['GET','POST'])
@app.route('/admin/event/<int:event_id>', methods=['GET','POST'])
def admin_event_form(event_id=None):
    if not session.get('is_admin'):
        flash("Admin only.")
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    event = None
    if event_id:
        cursor.execute("SELECT * FROM events WHERE id=%s", (event_id,))
        event = cursor.fetchone()

    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        location = request.form['location'].strip()
        start_dt = parse_dt_local(request.form['start_datetime'])
        end_dt = parse_dt_local(request.form['end_datetime'])
        capacity = int(request.form['capacity']) if request.form.get('capacity') else None
        approved = 1 if request.form.get('approved') else 0

        if event_id:
            cursor.execute("""
                UPDATE events SET title=%s, description=%s, location=%s,
                    start_datetime=%s, end_datetime=%s, capacity=%s, approved=%s
                WHERE id=%s
            """, (title, description, location, start_dt, end_dt, capacity, approved, event_id))
            flash("Event updated.")
        else:
            cursor.execute("""
                INSERT INTO events (title,description,location,start_datetime,end_datetime,capacity,approved)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, (title, description, location, start_dt, end_dt, capacity, approved))
            flash("Event created.")
        conn.commit()
        cursor.close(); conn.close()
        return redirect(url_for('admin_dashboard'))

    cursor.close(); conn.close()
    return render_template('main.html', page='admin_event_form', event=event)

@app.route('/admin/delete/<int:event_id>', methods=['POST'])
def admin_delete_event(event_id):
    if not session.get('is_admin'):
        flash("Admin only.")
        return redirect(url_for('login'))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM events WHERE id=%s", (event_id,))
    conn.commit()
    cursor.close(); conn.close()
    flash("Event deleted.")
    return redirect(url_for('admin_dashboard'))

# NEW: view registrants for a given event
@app.route('/admin/event/<int:event_id>/registrations')
def admin_event_registrations(event_id):
    if not session.get('is_admin'):
        flash("Admin only.")
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    # Get event info
    cursor.execute("SELECT * FROM events WHERE id=%s", (event_id,))
    event = cursor.fetchone()

    # Get list of registrants (name, email)
    cursor.execute("""
        SELECT u.id AS user_id, u.name, u.email
        FROM users u
        JOIN registrations r ON u.id = r.user_id
        WHERE r.event_id = %s
        ORDER BY u.name
    """, (event_id,))
    registrants = cursor.fetchall()

    # Count
    reg_count = len(registrants)

    cursor.close(); conn.close()
    return render_template('main.html', page='admin_event_registrations',
                           event=event, registrants=registrants, reg_count=reg_count)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
