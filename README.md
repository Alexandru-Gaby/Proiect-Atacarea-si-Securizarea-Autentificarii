# AuthX – Break the Login
## Versiunea SECURIZATĂ (branch: fixed)

## Descriere

AuthX este o aplicație web de autentificare construită pentru
proiectul 2 – "Break the Login" din cadrul cursului
**Dezvoltarea Aplicațiilor Software Securizate**,
Facultatea de Matematică și Informatică, Universitatea din București.

Această versiune reprezintă implementarea **securizată (v2)**,
în care toate cele 6 vulnerabilități au fost remediate.

---

## Stack tehnologic

| Componentă   | Tehnologie         |
|--------------|--------------------|
| Backend      | Python 3.11, Flask |
| Bază de date | MySQL 8.0          |
| Frontend     | HTML, CSS (Jinja2) |
| Editor       | Visual Studio Code |
| Mediu        | VMware, Windows 11 |

---

## Vulnerabilități remediate în această versiune

| # | Vulnerabilitate | Fix aplicat |
|---|----------------|-------------|
| 4.1 | Password Policy slab | Validare: minim 8 caractere, o literă mare, o cifră |
| 4.2 | Stocare MD5 fără salt | Înlocuit cu bcrypt + salt automat |
| 4.3 | Brute Force | Blocare cont după 3 încercări eșuate |
| 4.4 | User Enumeration | Mesaj unic generic: "Credentiale invalide" |
| 4.5 | Sesiuni nesecurizate | HttpOnly, SameSite=Lax, expirare 30 minute |
| 4.6 | Token resetare nesigur | secrets.token_hex(32), expirare 15 min, one-time use |
---



## Instalare și rulare locală

### 1. Clonează repository-ul și treci pe branch-ul fixed

```bash
git clone https://github.com/[username]/authx.git
cd authx
git checkout fixed
```

### 2. Creează și activează mediul virtual Python

```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Instalează dependențele

```bash
pip install flask flask-mysqldb bcrypt python-dotenv
```

### 4. Configurează baza de date

Deschide MySQL Workbench și rulează:

```sql
CREATE DATABASE IF NOT EXISTS authx;
USE authx;

CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(254) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role ENUM('USER','ADMIN') NOT NULL DEFAULT 'USER',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    locked BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE tickets (
    id VARCHAR(36) PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    severity ENUM('LOW','MED','HIGH') NOT NULL,
    status ENUM('OPEN','IN_PROGRESS','RESOLVED') NOT NULL DEFAULT 'OPEN',
    owner_id VARCHAR(36) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

CREATE TABLE audit_logs (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36),
    action VARCHAR(50) NOT NULL,
    resource VARCHAR(30),
    resource_id VARCHAR(36),
    ip_address VARCHAR(45),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE password_reset_tokens (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    token TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### 5. Configurează fișierul .env

```bash
MYSQL_HOST=localhost
MYSQL_USER=root
MYSQL_PASSWORD=root
MYSQL_DB=authx
SECRET_KEY=supersecretkey123
```

### 6. Pornește aplicația

```bash
python app.py
```

Deschide browserul la: **http://localhost:8080**

---

## Detalii despre fix-uri

### Fix 4.1 – Validare parolă complexă
```python
def is_strong_password(password):
    if len(password) < 8:
        return False, "Parola trebuie sa aiba minim 8 caractere."
    if not re.search(r'[A-Z]', password):
        return False, "Parola trebuie sa contina cel putin o litera mare."
    if not re.search(r'[0-9]', password):
        return False, "Parola trebuie sa contina cel putin o cifra."
    return True, ""
```

### Fix 4.2 – bcrypt cu salt automat
```python
import bcrypt
# Înregistrare:
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
# Login:
bcrypt.checkpw(password.encode(), user['password_hash'].encode())
```

### Fix 4.3 – Blocare cont după 5 încercări
```python
MAX_FAILED = 3
# Se numără LOGIN_FAILED din audit_logs
# După MAX_FAILED: UPDATE users SET locked=TRUE
```

### Fix 4.4 – Mesaj generic la login
```python
GENERIC = 'Credentiale invalide.'
# Același mesaj indiferent dacă userul nu există
# sau parola este greșită
```

### Fix 4.5 – Cookie-uri securizate
```python
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
session.permanent = True
```

### Fix 4.6 – Token securizat one-time
```python
import secrets
token = secrets.token_hex(32)           # 64 caractere aleatorii
expires = now + timedelta(minutes=15)   # expiră în 15 minute
# După folosire: UPDATE SET used=TRUE
# Verificare: WHERE token=%s AND used=FALSE AND expires_at > NOW()
```

---

## Retest – confirmare că atacurile nu mai funcționează

| # | Atac | Rezultat după fix |
|---|------|-------------------|
| 4.1 | Parolă "1" | ❌ Respinsă cu mesaj de eroare |
| 4.2 | CrackStation pe hash | ❌ Hash bcrypt nu poate fi spart |
| 4.3 | Script brute force | ❌ Cont blocat după 3 încercări |
| 4.4 | User enumeration | ❌ Același mesaj pentru orice caz |
| 4.5 | document.cookie în consolă | ❌ Cookie-ul nu este accesibil din JS |
| 4.6 | Token folosit a doua oară | ❌ "Token invalid, expirat sau deja folosit" |