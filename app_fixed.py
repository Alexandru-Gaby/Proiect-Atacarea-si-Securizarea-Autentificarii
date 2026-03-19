from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from config import Config
import uuid
import bcrypt
import secrets
import datetime
import re

app = Flask(__name__)
app.config.from_object(Config)

# ── FIX 4.5: cookie-uri securizate ───────────────────────────────
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE']   = False   # True doar cu HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=30)

mysql = MySQL(app)

MAX_FAILED = 3   # FIX 4.3: blocare dupa 3 incercari


def log_action(user_id, action, resource=None, resource_id=None, ip=None):
    curs = mysql.connection.cursor()
    curs.execute(
        """INSERT INTO audit_logs (id, user_id, action, resource, resource_id, ip_address)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (str(uuid.uuid4()), user_id, action, resource, resource_id, ip)
    )
    mysql.connection.commit()
    curs.close()

# validare parola complexa (FIX 4.1)
def is_strong_password(password):
    if len(password) < 8:
        return False, "Parola trebuie sa aiba minim 8 caractere."
    if not re.search(r'[A-Z]', password):
        return False, "Parola trebuie sa contina cel putin o litera mare."
    if not re.search(r'[0-9]', password):
        return False, "Parola trebuie sa contina cel putin o cifra."
    return True, ""

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        # fix 4.1: validam complexitatea parolei
        ok, msg = is_strong_password(password)
        if not ok:
            flash(msg, 'danger')
            return render_template('register.html')

        # fix 4.2: bcrypt genereaza salt automat
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        cur = mysql.connection.cursor()
        try:
            cur.execute(
                "INSERT INTO users (id, email, password_hash, role) VALUES (%s, %s, %s, %s)",
                (str(uuid.uuid4()), email, password_hash, 'USER')
            )
            mysql.connection.commit()
            flash('Cont creat cu succes! Te poti loga.', 'success')
            return redirect(url_for('login'))
        except Exception:
            # FIX: mesaj generic, fara detalii tehnice din DB
            flash('Emailul este deja folosit sau datele sunt invalide.', 'danger')
        finally:
            cur.close()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        # FIX 4.4: mesaj unic indiferent de motiv
        GENERIC = 'Credentiale invalide.'

        if not user:
            flash(GENERIC, 'danger')
            cur.close()
            return render_template('login.html')

        # FIX 4.3: verificam daca contul e blocat
        if user['locked']:
            flash('Contul este blocat. Contacteaza administratorul.', 'danger')
            log_action(user['id'], 'LOGIN_BLOCKED', 'auth', user['id'], request.remote_addr)
            cur.close()
            return render_template('login.html')

        # FIX 4.2: verificare bcrypt
        if not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
            # FIX 4.3: numaram incercarile esuate si blocam dupa MAX_FAILED
            cur.execute(
                "SELECT COUNT(*) as cnt FROM audit_logs WHERE user_id=%s AND action='LOGIN_FAILED'",
                (user['id'],)
            )
            row = cur.fetchone()
            failed_count = row['cnt'] + 1

            if failed_count >= MAX_FAILED:
                cur.execute("UPDATE users SET locked=TRUE WHERE id=%s", (user['id'],))
                mysql.connection.commit()

            log_action(user['id'], 'LOGIN_FAILED', 'auth', user['id'], request.remote_addr)
            flash(GENERIC, 'danger')
            cur.close()
            return render_template('login.html')

        # Login reusit: deblocam contul si resetam contorul
        cur.execute(
            "UPDATE users SET locked=FALSE WHERE id=%s",
            (user['id'],)
        )
        mysql.connection.commit()
        cur.close()

        # FIX 4.5: sesiune cu expirare de 30 de minute
        session.permanent = True
        session['user_id'] = user['id']
        session['email']   = user['email']
        session['role']    = user['role']

        log_action(user['id'], 'LOGIN_SUCCESS', 'auth', user['id'], request.remote_addr)
        return redirect(url_for('dashboard'))

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', email=session['email'])

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        log_action(user_id, 'LOGOUT', 'auth', user_id, request.remote_addr)
    session.clear()
    flash('Te-ai delogat cu succes.', 'info')
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        # FIX 4.4: acelasi mesaj indiferent daca emailul exista sau nu
        flash('Daca emailul exista, vei primi un link de resetare.', 'info')

        if user:
            # FIX 4.6: token aleator securizat (64 caractere hex)
            token   = secrets.token_hex(32)
            # FIX 4.6: expirare scurta – 15 minute
            expires = datetime.datetime.now() + datetime.timedelta(minutes=15)

            cur.execute(
                """INSERT INTO password_reset_tokens (id, user_id, token, expires_at)
                   VALUES (%s, %s, %s, %s)""",
                (str(uuid.uuid4()), user['id'], token, expires)
            )
            mysql.connection.commit()

            # îl afișăm in terminal pentru demo:
            print(f"[DEMO] Link: http://localhost:8080/reset-password?token={token}")

        cur.close()

    return render_template('forgot_password.html')


# FIX 4.6 – verifica expirare + marcare token ca folosit
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    token = request.args.get('token', '')

    if request.method == 'POST':
        token        = request.form.get('token', '')
        new_password = request.form.get('new_password', '')

        # FIX 4.1: validam parola si la resetare
        ok, msg = is_strong_password(new_password)
        if not ok:
            flash(msg, 'danger')
            return render_template('reset_password.html', token=token)

        cur = mysql.connection.cursor()
        # FIX 4.6: verifica token valid, neutilizat si neexpirat
        cur.execute(
            """SELECT * FROM password_reset_tokens
               WHERE token = %s AND used = FALSE AND expires_at > NOW()""",
            (token,)
        )
        reset = cur.fetchone()

        if reset:
            # FIX 4.2: bcrypt
            new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
            cur.execute(
                "UPDATE users SET password_hash = %s WHERE id = %s",
                (new_hash, reset['user_id'])
            )
            # FIX 4.6: marcam token-ul ca folosit → nu mai poate fi reutilizat
            cur.execute(
                "UPDATE password_reset_tokens SET used = TRUE WHERE id = %s",
                (reset['id'],)
            )
            mysql.connection.commit()
            flash('Parola a fost resetata cu succes!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Token invalid, expirat sau deja folosit.', 'danger')

        cur.close()

    return render_template('reset_password.html', token=token)

@app.errorhandler(404)
def not_found(e):
    return render_template('login.html'), 404

@app.errorhandler(500)
def server_error(e):
    app.logger.error(f"Eroare interna: {e}")
    flash('A aparut o eroare. Incearca din nou.', 'danger')
    return redirect(url_for('home')), 500

if __name__ == '__main__':
    # FIX: debug=False
    app.run(debug=False, host='0.0.0.0', port=8080)