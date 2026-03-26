# AuthX – Break the Login
## Versiunea VULNERABILĂ (branch: vulnerable)

---

## Descriere

AuthX este o aplicație web de autentificare construită pentru
proiectul – "Break the Login" din cadrul cursului
**Dezvoltarea Aplicațiilor Software Securizate**,
Facultatea de Matematică și Informatică, Universitatea din București.

Această versiune reprezintă implementarea **inițială vulnerabilă (MVP)**,
care conține în mod intenționat 6 vulnerabilități de securitate
ce urmează să fie demonstrate și remediate.

---

## Stack tehnologic

| Componentă   | Tehnologie         |
|--------------|--------------------|
| Backend      | Python 3.11, Flask |
| Bază de date | MySQL 8.0          |
| Frontend     | HTML, CSS |
| Editor       | Visual Studio Code |
| Mediu        | VMware, Windows 11 |

---

## Vulnerabilități prezente în această versiune

| # | Vulnerabilitate | Descriere scurtă |
|---|----------------|-----------------|
| 4.1 | Password Policy slab | Orice parolă este acceptată, inclusiv "1" |
| 4.2 | Stocare MD5 fără salt | Parolele sunt hash-uite cu MD5, ușor de spart |
| 4.3 | Brute Force | Nu există rate limiting sau blocare cont |
| 4.4 | User Enumeration | Mesaje diferite pentru user inexistent vs parolă greșită |
| 4.5 | Sesiuni nesecurizate | Cookie fără HttpOnly, Secure sau SameSite |
| 4.6 | Token resetare nesigur | Token predictibil (timestamp), fără expirare, reutilizabil |

---


## Instalare și rulare locală

### 1. Clonează repository-ul și comută pe branch-ul vulnerabil

```bash
git clone https://github.com/[username]/authx.git
cd authx
git checkout vulnerable
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


---

## Branch-uri disponibile

| Branch | Descriere |
|--------|-----------|
| `vulnerable` | Versiunea cu vulnerabilități (acest branch) |
| `fixed` | Versiunea securizată cu toate fix-urile |

---