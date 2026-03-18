from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from config import Config
import uuid
import hashlib
import datetime

app = Flask(__name__)
app.config.from_object(Config)

mysql = MySQL(app)

def log_action(user_id, action, resource=None, resource_id=None, ip=None):
    curs = mysql.connection.cursor()
    curs.execute(
        """INSERT INTO audit_logs (id, user_id, action, resource, resource_id, ip_address)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (str(uuid.uuid4()), user_id, action, resource, resource_id, ip)
    )
    mysql.connection.commit()
    curs.close()


def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

#Funcționalitate 3.1
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']

        password_hash = hashlib.md5(password.encode()).hexdigest()

        curs = mysql.connection.cursor()
        try:
            curs.execute(
                "INSERT INTO users(id, email, password_hash, role) VALUES (%s, %s, %s, %s)",
                (str(uuid.uuid4()), email, password_hash, 'USER')
            )
            mysql.connection.commit()
            flash('Cont creat cu success! Te poti loga.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            #Afisez eroarea exacta din baza de date 
            flash(f'Eroare: {str(e)}', 'danger')
        finally:
            curs.close()

    return render_template('register.html')

#Funcționalitate 3.2 
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        #md5 fara salt
        password_hash = hashlib.md5(password.encode()).hexdigest()

        curs = mysql.connection.cursor()
        curs.execute("SELECT * FROM users WHE" \
        "RE email = %s", (email,))
        user = curs.fetchone()
        curs.close()

        if not user:
            #Vulnerabilitatea 4.4 mesaj diferit
            flash('Utilizatorul nu exista!', 'danger')
            return render_template('login.html'
            ''
            '')

        if user['password_hash'] != password_hash:
            flash('Parola gresita!', 'danger')
            log_action(user['id'], 'LOGIN_FAILED', 'auth', user['id'], request.remote_addr)
            return render_template('login.html')

        #Vulnerabilitatea 4.5 sesiune fara expirare, cookie fara flag de securitate
        session['user_id'] = user['id']
        session['email'] = user['email']
        session['role'] = user['role']

        log_action(user['id'], 'LOGIN_SUCCESS', 'auth', user['id'], request.remote_addr)
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', email=session['email'])

#Funcționalitate 3.3
@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        log_action(user_id, 'LOGOUT', 'auth', user_id, request.remote_addr)
    session.clear()
    flash('Te-ai delogat', 'info')
    return redirect(url_for('login'))

#VULNERABILITATE 4.4 - confirm daca emailul exista sau nu
#VULNERABILITATE 4.6 - token (timestamp), reutilizabil
#Funcționalitate 3.4
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        curs = mysql.connection.cursor()
        curs.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = curs.fetchone()

        if user:
            #VULNERABILITATE 4.6 timestamp
            token = str(int(datetime.datetime.now().timestamp()))
            expires = datetime.datetime.now() + datetime.timedelta(hours=24) #prea lung

            curs.execute(
                """INSERT INTO password_reset_tokens (id, user_id, token, expires_at)
                   VALUES (%s, %s, %s, %s)""",
                (str(uuid.uuid4()), user['id'], token, expires)
            )
            mysql.connection.commit()


            #token afisat in browser nu pe mail
            flash(f'Token resetare: {token}', 'info')
        else:
            flash('Emailul nu este inregistrat!', 'danger')

        curs.close()
    return render_template('forgot_password.html')


@app.route('/reset-password', methods=['GET','POST'])
def reset_password():
    token = request.args.get('token', '')
    if request.method =='POST':
        token = request.form['token']
        new_password = request.form['new_password']

        curs = mysql.connection.cursor()
        #vulnerabilitatea 4.6 nu verificam daca a expirat sau e deja folosit
        curs.execute("SELECT * FROM password_reset_tokens WHERE token = %s", (token,))
        reset = curs.fetchone() 

        if reset:
            #vulnerabilitate 4.2 MD5 fără salt
            new_hash = hashlib.md5(new_password.encode()).hexdigest()
            curs.execute(
                "UPDATE users SET password_hash = %s WHERE id = %s",
                (new_hash, reset['user_id'])
            )           
            #VULNERABIL 4.6 tokenul nu e marcat ca folosit
            mysql.connection.commit()
            flash('Parola a fost resetata!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Token invalid!', 'danger')

        curs.close()
    return render_template('reset_password.html', token=token)

if __name__ == '__main__':
    #VULNERABILITATE debug=TRUE expune stack trace-uri
    app.run(debug=True, host='0.0.0.0', port=8080)
