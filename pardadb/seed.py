"""Synthetic bank data (all values invented, cards pass Luhn, Aadhaar passes Verhoeff) for SQLite and MySQL."""
import os
import random
import sqlite3

from .backends import MYSQL, SQLITE_PATH

FIRST = ["Ravi", "Priya", "Arjun", "Sneha", "Kiran", "Lakshmi", "Venkatesh", "Ananya", "Rahul", "Divya",
         "Suresh", "Meera", "Aditya", "Kavya", "Naveen", "Pooja", "Srinivas", "Harika", "Vikram", "Swathi"]
LAST = ["Kumar", "Sharma", "Reddy", "Iyer", "Naidu", "Rao", "Patel", "Varma", "Chowdary", "Menon"]
CITIES = ["Visakhapatnam", "Vijayawada", "Guntur", "Tirupati", "Hyderabad", "Nellore", "Kakinada"]
MERCHANTS = ["Amazon", "Swiggy", "IRCTC", "BigBasket", "Apollo Pharmacy", "Reliance Digital"]

_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],
      [5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],
      [4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
_INV = [0,4,3,2,1,5,6,7,8,9]


def verhoeff_digit(num):
    c = 0
    for i, d in enumerate(reversed(num)):
        c = _D[c][_P[(i + 1) % 8][int(d)]]
    return str(_INV[c])


def luhn_digit(num):
    s = 0
    for i, d in enumerate(reversed(num)):
        d = int(d)
        if i % 2 == 0:
            d *= 2
            d -= 9 if d > 9 else 0
        s += d
    return str((10 - s % 10) % 10)


def gen(n=60, seed=7):
    rnd = random.Random(seed)
    customers, txns = [], []
    for i in range(1, n + 1):
        name = f"{rnd.choice(FIRST)} {rnd.choice(LAST)}"
        base = rnd.choice(["4111", "5500", "4012", "5105"]) + "".join(rnd.choice("0123456789") for _ in range(11))
        card = base + luhn_digit(base)
        card = "-".join(card[j:j + 4] for j in range(0, 16, 4))
        a = str(rnd.randint(2, 9)) + "".join(rnd.choice("0123456789") for _ in range(10))
        a = a + verhoeff_digit(a)
        aadhaar = f"{a[:4]} {a[4:8]} {a[8:]}"
        pan = "".join(rnd.choice("ABCDEFGHJKLMNPQRSTUVWXYZ") for _ in range(3)) + "P" + name.split()[1][0] + \
            f"{rnd.randint(1000, 9999)}" + rnd.choice("ABCDEFGHJKLMNPQRSTUVWXYZ")
        email = f"{name.split()[0].lower()}.{name.split()[1].lower()[:1]}{i}@example.com"
        phone = f"+91 {rnd.choice('6789')}{rnd.randint(1000, 9999)} {rnd.randint(10000, 99999)}"
        bal = round(rnd.uniform(500, 2500000), 2)
        city = rnd.choice(CITIES)
        notes = rnd.choice([
            f"Customer {name} called from {phone} about a blocked card.",
            f"KYC verified for {name}, PAN {pan}.",
            "Requested new cheque book.",
            f"Address change requested by {name.split()[0]}; e-mail sent to {email}.",
        ])
        customers.append((i, name, email, phone, card, aadhaar, pan, bal, city, notes))
        for k in range(rnd.randint(1, 3)):
            txns.append((len(txns) + 1, i, card, round(rnd.uniform(50, 25000), 2), rnd.choice(MERCHANTS)))
    return customers, txns


DDL = [
    """CREATE TABLE customers (id INTEGER PRIMARY KEY, full_name VARCHAR(80), email VARCHAR(120), phone VARCHAR(20),
       card_no VARCHAR(19), aadhaar VARCHAR(14), pan VARCHAR(10), balance DECIMAL(14,2), city VARCHAR(40), notes TEXT)""",
    """CREATE TABLE transactions (id INTEGER PRIMARY KEY, customer_id INTEGER, card_no VARCHAR(19),
       amount DECIMAL(12,2), merchant VARCHAR(40))""",
]


def seed_sqlite(path=SQLITE_PATH):
    if os.path.exists(path):
        os.remove(path)
    c, t = gen()
    con = sqlite3.connect(path)
    for d in DDL:
        con.execute(d)
    con.executemany("INSERT INTO customers VALUES (?,?,?,?,?,?,?,?,?,?)", c)
    con.executemany("INSERT INTO transactions VALUES (?,?,?,?,?)", t)
    con.commit()
    con.close()


def seed_mysql(cfg=MYSQL):
    import pymysql

    db = cfg["database"]
    con = pymysql.connect(**{k: v for k, v in cfg.items() if k != "database"}, autocommit=True)
    cur = con.cursor()
    cur.execute(f"DROP DATABASE IF EXISTS `{db}`")
    cur.execute(f"CREATE DATABASE `{db}`")
    cur.execute(f"USE `{db}`")
    c, t = gen()
    for d in DDL:
        cur.execute(d)
    cur.executemany("INSERT INTO customers VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", c)
    cur.executemany("INSERT INTO transactions VALUES (%s,%s,%s,%s,%s)", t)
    con.close()
