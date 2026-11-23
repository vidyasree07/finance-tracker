"""Run with: python3 -m unittest -v"""
import os
import sqlite3
import tempfile
import unittest

from app import create_app, to_cents


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.client = create_app(self.tmp.name, secret_key="test-secret").test_client()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def register(self, email="a@example.com", password="password123"):
        return self.client.post("/api/register", json={"email": email, "password": password})

    def login_headers(self, email="a@example.com", password="password123"):
        self.register(email, password)
        token = self.client.post("/api/login", json={"email": email, "password": password}).get_json()["token"]
        return {"Authorization": f"Bearer {token}"}

    def add(self, headers, **overrides):
        body = {"type": "expense", "category": "Food", "amount": "12.50", "date": "2026-11-05", "note": "lunch"}
        body.update(overrides)
        return self.client.post("/api/transactions", json=body, headers=headers)


class MoneyTests(unittest.TestCase):
    def test_to_cents(self):
        self.assertEqual(to_cents("12.50"), 1250)
        self.assertEqual(to_cents("0.30"), 30)
        self.assertEqual(to_cents(5), 500)

    def test_rejects_bad_amounts(self):
        for bad in ["0", "-5", "abc", "1.005", None, True, "NaN", "Infinity"]:
            with self.assertRaises(ValueError, msg=str(bad)):
                to_cents(bad)


class AuthTests(Base):
    def test_register_login_flow(self):
        self.assertEqual(self.register().status_code, 201)
        res = self.client.post("/api/login", json={"email": "a@example.com", "password": "password123"})
        self.assertEqual(res.status_code, 200)
        self.assertIn("token", res.get_json())

    def test_duplicate_email_rejected_case_insensitively(self):
        self.register("a@example.com")
        self.assertEqual(self.register("A@Example.com").status_code, 409)

    def test_weak_password_and_bad_email_rejected(self):
        self.assertEqual(self.register(password="short").status_code, 400)
        self.assertEqual(self.register(email="not-an-email").status_code, 400)

    def test_wrong_password_and_unknown_email_give_same_message(self):
        self.register()
        wrong = self.client.post("/api/login", json={"email": "a@example.com", "password": "wrongpass1"})
        unknown = self.client.post("/api/login", json={"email": "nobody@example.com", "password": "password123"})
        self.assertEqual((wrong.status_code, unknown.status_code), (401, 401))
        self.assertEqual(wrong.get_json(), unknown.get_json())

    def test_password_is_stored_hashed(self):
        self.register(password="password123")
        stored = sqlite3.connect(self.tmp.name).execute("SELECT password_hash FROM users").fetchone()[0]
        self.assertNotIn("password123", stored)
        self.assertTrue(stored.startswith(("scrypt:", "pbkdf2:")))

    def test_endpoints_require_a_valid_token(self):
        self.assertEqual(self.client.get("/api/transactions").status_code, 401)
        self.assertEqual(self.client.get("/api/summary", headers={"Authorization": "Bearer garbage"}).status_code, 401)
        headers = self.login_headers()
        tampered = {"Authorization": headers["Authorization"][:-3] + "abc"}
        self.assertEqual(self.client.get("/api/transactions", headers=tampered).status_code, 401)


class TransactionTests(Base):
    def test_create_list_update_delete(self):
        h = self.login_headers()
        created = self.add(h)
        self.assertEqual(created.status_code, 201)
        tx_id = created.get_json()["id"]
        self.assertEqual(created.get_json()["amount"], "12.50")
        self.assertEqual(len(self.client.get("/api/transactions", headers=h).get_json()), 1)

        upd = self.client.put(f"/api/transactions/{tx_id}", headers=h, json={
            "type": "expense", "category": "Food", "amount": "20", "date": "2026-11-06", "note": "dinner"})
        self.assertEqual((upd.status_code, upd.get_json()["amount"]), (200, "20.00"))
        self.assertEqual(self.client.delete(f"/api/transactions/{tx_id}", headers=h).status_code, 200)
        self.assertEqual(self.client.get("/api/transactions", headers=h).get_json(), [])

    def test_validation(self):
        h = self.login_headers()
        for bad in ({"amount": "0"}, {"amount": "-3"}, {"amount": "1.234"}, {"amount": "abc"}, {"type": "gift"},
                    {"category": "  "}, {"date": "2026-13-40"}, {"date": "yesterday"}, {"category": "x" * 41}):
            self.assertEqual(self.add(h, **bad).status_code, 400, msg=str(bad))

    def test_users_cannot_see_or_change_each_others_data(self):
        a = self.login_headers("a@example.com")
        b = self.login_headers("b@example.com")
        tx_id = self.add(a).get_json()["id"]
        self.assertEqual(self.client.get("/api/transactions", headers=b).get_json(), [])
        self.assertEqual(self.client.delete(f"/api/transactions/{tx_id}", headers=b).status_code, 404)
        body = {"type": "expense", "category": "Food", "amount": "1", "date": "2026-11-05"}
        self.assertEqual(self.client.put(f"/api/transactions/{tx_id}", headers=b, json=body).status_code, 404)
        self.assertEqual(len(self.client.get("/api/transactions", headers=a).get_json()), 1)     # still there

    def test_sql_injection_attempt_is_stored_as_plain_text(self):
        h = self.login_headers()
        evil = "x'); DROP TABLE transactions;--"
        self.assertEqual(self.add(h, category=evil[:40]).status_code, 201)
        self.assertEqual(len(self.client.get("/api/transactions", headers=h).get_json()), 1)    # table still exists
        login = self.client.post("/api/login", json={"email": "a@example.com' OR '1'='1", "password": "x"})
        self.assertEqual(login.status_code, 401)

    def test_month_filter(self):
        h = self.login_headers()
        self.add(h, date="2026-11-05")
        self.add(h, date="2026-12-01")
        self.assertEqual(len(self.client.get("/api/transactions?month=2026-11", headers=h).get_json()), 1)
        self.assertEqual(self.client.get("/api/transactions?month=nov", headers=h).status_code, 400)


class SummaryTests(Base):
    def test_totals_and_categories_are_exact(self):
        h = self.login_headers()
        self.add(h, type="income", category="Salary", amount="1000.00")
        self.add(h, category="Food", amount="0.10")
        self.add(h, category="Food", amount="0.20")                    # floats would give 0.30000000000000004
        self.add(h, category="Rent", amount="400")
        s = self.client.get("/api/summary?month=2026-11", headers=h).get_json()
        self.assertEqual((s["income"], s["expense"], s["net"]), ("1000.00", "400.30", "599.70"))
        self.assertEqual(s["expense_by_category"], {"Rent": "400.00", "Food": "0.30"})

    def test_budget_alerts(self):
        h = self.login_headers()
        self.client.put("/api/budgets/Food", headers=h, json={"limit": "100"})
        self.add(h, category="Food", amount="85")
        alerts = self.client.get("/api/summary?month=2026-11", headers=h).get_json()["budget_alerts"]
        self.assertEqual([a["status"] for a in alerts], ["warning"])
        self.add(h, category="Food", amount="30")
        alerts = self.client.get("/api/summary?month=2026-11", headers=h).get_json()["budget_alerts"]
        self.assertEqual([a["status"] for a in alerts], ["over"])

    def test_budget_validation_and_update(self):
        h = self.login_headers()
        self.assertEqual(self.client.put("/api/budgets/Food", headers=h, json={"limit": "-5"}).status_code, 400)
        self.assertEqual(self.client.put("/api/budgets/Food", headers=h, json={"limit": "50"}).status_code, 200)
        self.assertEqual(self.client.put("/api/budgets/Food", headers=h, json={"limit": "75"}).get_json()["limit"], "75.00")

    def test_summary_is_per_user(self):
        a, b = self.login_headers("a@example.com"), self.login_headers("b@example.com")
        self.add(a, amount="50")
        self.assertEqual(self.client.get("/api/summary?month=2026-11", headers=b).get_json()["expense"], "0.00")


class PageTests(Base):
    def test_front_end_page_is_served(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Personal Finance Tracker", res.data)


if __name__ == "__main__":
    unittest.main()
