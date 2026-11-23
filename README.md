# Personal Finance Tracker: a Full-Stack App (Flask + SQLite + JavaScript)

A complete full-stack web app: users register and log in, record income and expenses, see a monthly summary with a spending-by-category chart, and get **budget alerts**. The back end is a REST API (Python, Flask, SQLite) and the front end is a single-page app in plain JavaScript (HTML, CSS, `fetch`). 18 automated tests cover the API.

Built around what a **bank** cares about:
- **Passwords are hashed** (never stored as plain text) and logins use **signed tokens that expire** after 8 hours.
- **Parameterized SQL** everywhere, so SQL injection does not work (there is a test that tries it).
- **Per-user data isolation:** user B cannot read, change or delete user A's records (tested).
- **Money is stored as whole cents**, not floats, so totals are exact (a test proves `0.10 + 0.20 = 0.30`).
- **Input validation** with clear error messages and correct status codes (400, 401, 404, 409).
- The login message is the same for "unknown email" and "wrong password", so attackers cannot discover which emails exist.
- The front end builds page content with `textContent`, so user text can never run as HTML or script (XSS protection).

**Tech:** Python, Flask, SQLite, SQL, REST APIs, JavaScript (DOM, Fetch API), HTML/CSS, authentication, unit testing

## Run (Mac Terminal)
```bash
cd ~/Downloads/cfg-fullstack/1-personal-finance-tracker
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 -m unittest -v          # 18 tests
python3 app.py                  # then open http://127.0.0.1:5003 in your browser
```
In the browser: register with any email and an 8+ character password, add an income and a few expenses, set a budget for "Food", and watch the alert appear when you go over it. Stop the server with `Ctrl + C`.

I tested the API and the page's JavaScript syntax. I could not click through the page in a browser, so if any button misbehaves, tell me exactly what you clicked and what you saw.

## Be ready to explain (interviews)
- **Hashing vs encryption:** why passwords are hashed, and what a salt is.
- **Token authentication:** what a signed token is, how it expires, and why it is checked on every request.
- **SQL injection:** what it is and why `?` placeholders stop it.
- **Why integer cents:** what goes wrong with floating-point money.
- **Why return 404 (not 403) for another user's record:** it does not reveal that the record exists.
- **REST design:** which status code you return and why.
- **XSS:** why you use `textContent` instead of `innerHTML`.
- **Index:** why `idx_tx_user_date` exists and which query it speeds up.
- **What you would add for production:** HTTPS, rate limiting on login (brute force), refresh tokens, a React front end, a PostgreSQL database.

## Make it yours (add one)
Add a category filter to the API. In `app.py`, inside `list_transactions`, add these lines just above the line `rows = get_db().execute(sql + " ORDER BY tx_date DESC, id DESC", params).fetchall()`:
```python
        category = request.args.get("category", "").strip()
        if category:
            sql += " AND category = ?"
            params.append(category)
```
and add this test in `test_app.py`, above `def test_month_filter(self):` (same indentation):
```python
    def test_category_filter(self):
        h = self.login_headers()
        self.add(h, category="Food")
        self.add(h, category="Rent")
        res = self.client.get("/api/transactions?category=Food", headers=h).get_json()
        self.assertEqual([t["category"] for t in res], ["Food"])
```
Run the tests (19 should pass). Then write 3 lines in `NOTES.md` about what you would test next.

## Push to GitHub
```bash
cd ~/Downloads/cfg-fullstack/1-personal-finance-tracker && ls app.py && git init -b main && git add . && git commit -m "Add full-stack personal finance tracker" && gh repo create personal-finance-tracker --public --source=. --remote=origin --push
```
