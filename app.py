"""
Personal Finance Tracker: a full-stack app (Flask REST API + SQLite + JavaScript front end).

Features: user accounts (hashed passwords, signed expiring tokens), income/expense tracking,
monthly summary, category budgets with alerts.
Security basics a bank cares about: password hashing, parameterized SQL (no SQL injection),
per-user data isolation, input validation, money stored as integer cents (no float errors).

Run:  python3 app.py     then open http://127.0.0.1:5003
"""
import os
import re
import secrets
import sqlite3
from datetime import date, datetime
from decimal import Decimal, InvalidOperation

from flask import Flask, g, jsonify, request, send_from_directory
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
TYPES = {"income", "expense"}
TOKEN_MAX_AGE = 8 * 3600          # tokens expire after 8 hours

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    type TEXT NOT NULL CHECK (type IN ('income', 'expense')),
    category TEXT NOT NULL,
    amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
    note TEXT NOT NULL DEFAULT '',
    tx_date TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS budgets (
    user_id INTEGER NOT NULL REFERENCES users(id),
    category TEXT NOT NULL,
    limit_cents INTEGER NOT NULL CHECK (limit_cents > 0),
    PRIMARY KEY (user_id, category)
);
CREATE INDEX IF NOT EXISTS idx_tx_user_date ON transactions(user_id, tx_date);
"""


def to_cents(value):
    """Turns 12.50 into 1250. Rejects zero, negatives, junk, and more than 2 decimal places."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError("amount must be a number")
    try:
        d = Decimal(str(value))
    except InvalidOperation:
        raise ValueError("amount must be a number")
    if not d.is_finite() or d <= 0:
        raise ValueError("amount must be greater than 0")
    if d != d.quantize(Decimal("0.01")):
        raise ValueError("amount can have at most 2 decimal places")
    return int(d * 100)


def cents_to_str(cents):
    return f"{cents / 100:.2f}"


def create_app(db_path="finance.db", secret_key=None):
    app = Flask(__name__, static_folder="static")
    app.config["DB_PATH"] = db_path
    app.config["SECRET_KEY"] = secret_key or os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DB_PATH"])
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
        return g.db

    @app.teardown_appcontext
    def close_db(_):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    with sqlite3.connect(db_path) as conn:
        conn.executescript(SCHEMA)

    def error(message, status):
        return jsonify({"error": message}), status

    # ---------- authentication ----------
    def current_user_id():
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        try:
            return serializer.loads(header[7:], max_age=TOKEN_MAX_AGE)["uid"]
        except (BadSignature, SignatureExpired, KeyError):
            return None

    def login_required(view):
        from functools import wraps

        @wraps(view)
        def wrapper(*args, **kwargs):
            uid = current_user_id()
            if uid is None:
                return error("Authentication required", 401)
            g.user_id = uid
            return view(*args, **kwargs)
        return wrapper

    @app.post("/api/register")
    def register():
        data = request.get_json(silent=True) or {}
        email, password = str(data.get("email", "")).strip().lower(), data.get("password", "")
        if not EMAIL_RE.match(email):
            return error("A valid email is required", 400)
        if not isinstance(password, str) or len(password) < 8:
            return error("Password must be at least 8 characters", 400)
        try:
            cur = get_db().execute("INSERT INTO users (email, password_hash) VALUES (?, ?)",
                                   (email, generate_password_hash(password)))
            get_db().commit()
        except sqlite3.IntegrityError:
            return error("That email is already registered", 409)
        return jsonify({"id": cur.lastrowid, "email": email}), 201

    @app.post("/api/login")
    def login():
        data = request.get_json(silent=True) or {}
        email, password = str(data.get("email", "")).strip().lower(), data.get("password", "")
        row = get_db().execute("SELECT id, password_hash FROM users WHERE email = ?", (email,)).fetchone()
        # same message for unknown email and wrong password, so attackers cannot discover which emails exist
        if row is None or not isinstance(password, str) or not check_password_hash(row["password_hash"], password):
            return error("Invalid email or password", 401)
        return jsonify({"token": serializer.dumps({"uid": row["id"]})}), 200

    # ---------- transactions ----------
    def parse_transaction(data):
        """Returns (clean dict, None) or (None, error message)."""
        if not isinstance(data, dict):
            return None, "Request body must be JSON"
        tx_type = data.get("type")
        category = str(data.get("category", "")).strip()
        note = str(data.get("note", "")).strip()
        if tx_type not in TYPES:
            return None, "type must be 'income' or 'expense'"
        if not category or len(category) > 40:
            return None, "category is required (max 40 characters)"
        if len(note) > 200:
            return None, "note can be at most 200 characters"
        try:
            cents = to_cents(data.get("amount"))
            tx_date = date.fromisoformat(str(data.get("date", "")))
        except ValueError as e:
            return None, str(e) if "amount" in str(e) else "date must be a real date like 2026-11-30"
        return {"type": tx_type, "category": category, "amount_cents": cents, "note": note, "tx_date": tx_date.isoformat()}, None

    def tx_json(row):
        return {"id": row["id"], "type": row["type"], "category": row["category"],
                "amount": cents_to_str(row["amount_cents"]), "note": row["note"], "date": row["tx_date"]}

    @app.post("/api/transactions")
    @login_required
    def add_transaction():
        clean, err = parse_transaction(request.get_json(silent=True))
        if err:
            return error(err, 400)
        cur = get_db().execute(
            "INSERT INTO transactions (user_id, type, category, amount_cents, note, tx_date) VALUES (?,?,?,?,?,?)",
            (g.user_id, clean["type"], clean["category"], clean["amount_cents"], clean["note"], clean["tx_date"]))
        get_db().commit()
        row = get_db().execute("SELECT * FROM transactions WHERE id = ?", (cur.lastrowid,)).fetchone()
        return jsonify(tx_json(row)), 201

    @app.get("/api/transactions")
    @login_required
    def list_transactions():
        month = request.args.get("month", "")
        sql, params = "SELECT * FROM transactions WHERE user_id = ?", [g.user_id]
        if month:
            if not re.fullmatch(r"\d{4}-\d{2}", month):
                return error("month must look like 2026-11", 400)
            sql += " AND substr(tx_date, 1, 7) = ?"
            params.append(month)
        rows = get_db().execute(sql + " ORDER BY tx_date DESC, id DESC", params).fetchall()
        return jsonify([tx_json(r) for r in rows]), 200

    def owned_transaction(tx_id):
        return get_db().execute("SELECT * FROM transactions WHERE id = ? AND user_id = ?", (tx_id, g.user_id)).fetchone()

    @app.put("/api/transactions/<int:tx_id>")
    @login_required
    def update_transaction(tx_id):
        if owned_transaction(tx_id) is None:
            return error("Transaction not found", 404)         # also returned for other users' records
        clean, err = parse_transaction(request.get_json(silent=True))
        if err:
            return error(err, 400)
        get_db().execute("UPDATE transactions SET type=?, category=?, amount_cents=?, note=?, tx_date=? WHERE id=? AND user_id=?",
                         (clean["type"], clean["category"], clean["amount_cents"], clean["note"], clean["tx_date"], tx_id, g.user_id))
        get_db().commit()
        return jsonify(tx_json(owned_transaction(tx_id))), 200

    @app.delete("/api/transactions/<int:tx_id>")
    @login_required
    def delete_transaction(tx_id):
        if owned_transaction(tx_id) is None:
            return error("Transaction not found", 404)
        get_db().execute("DELETE FROM transactions WHERE id = ? AND user_id = ?", (tx_id, g.user_id))
        get_db().commit()
        return jsonify({"message": "Transaction deleted"}), 200

    # ---------- budgets and summary ----------
    @app.put("/api/budgets/<category>")
    @login_required
    def set_budget(category):
        category = category.strip()
        if not category or len(category) > 40:
            return error("category is required (max 40 characters)", 400)
        try:
            cents = to_cents((request.get_json(silent=True) or {}).get("limit"))
        except ValueError as e:
            return error(str(e).replace("amount", "limit"), 400)
        get_db().execute("INSERT INTO budgets (user_id, category, limit_cents) VALUES (?,?,?) "
                         "ON CONFLICT(user_id, category) DO UPDATE SET limit_cents = excluded.limit_cents",
                         (g.user_id, category, cents))
        get_db().commit()
        return jsonify({"category": category, "limit": cents_to_str(cents)}), 200

    @app.get("/api/summary")
    @login_required
    def summary():
        month = request.args.get("month") or date.today().strftime("%Y-%m")
        if not re.fullmatch(r"\d{4}-\d{2}", month):
            return error("month must look like 2026-11", 400)
        db = get_db()
        totals = {"income": 0, "expense": 0}
        for r in db.execute("SELECT type, SUM(amount_cents) AS s FROM transactions WHERE user_id=? AND substr(tx_date,1,7)=? GROUP BY type",
                            (g.user_id, month)):
            totals[r["type"]] = r["s"]
        spent = {r["category"]: r["s"] for r in db.execute(
            "SELECT category, SUM(amount_cents) AS s FROM transactions WHERE user_id=? AND type='expense' AND substr(tx_date,1,7)=? GROUP BY category",
            (g.user_id, month))}
        alerts = []
        for b in db.execute("SELECT category, limit_cents FROM budgets WHERE user_id = ?", (g.user_id,)):
            used = spent.get(b["category"], 0)
            if used > b["limit_cents"]:
                alerts.append({"category": b["category"], "status": "over", "spent": cents_to_str(used), "limit": cents_to_str(b["limit_cents"])})
            elif used >= 0.8 * b["limit_cents"]:
                alerts.append({"category": b["category"], "status": "warning", "spent": cents_to_str(used), "limit": cents_to_str(b["limit_cents"])})
        return jsonify({"month": month, "income": cents_to_str(totals["income"]), "expense": cents_to_str(totals["expense"]),
                        "net": cents_to_str(totals["income"] - totals["expense"]),
                        "expense_by_category": {k: cents_to_str(v) for k, v in sorted(spent.items(), key=lambda kv: -kv[1])},
                        "budget_alerts": alerts}), 200

    @app.get("/")
    def home():
        return send_from_directory(app.static_folder, "index.html")

    return app


if __name__ == "__main__":
    create_app().run(debug=False, port=5003)
