import os
import sqlite3
import tempfile
import unittest

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
os.environ["DB_PATH"] = _tmp.name
import app as shortener  # noqa: E402


class ShortenerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c = shortener.app.test_client()
        cls.admin = cls.register("admin@test.com")  # first user becomes admin
        cls.user = cls.register("user@test.com")

    @classmethod
    def register(cls, email):
        r = cls.c.post("/api/v1/auth/register", json={"email": email, "password": "password1"})
        return {"Authorization": "Bearer " + r.get_json()["token"]}

    def make(self, url="https://example.com/page", headers=None, **extra):
        return self.c.post("/api/v1/links", json={"url": url, **extra}, headers=headers or self.user)

    def test_register_validation_and_duplicate(self):
        bad = self.c.post("/api/v1/auth/register", json={"email": "x", "password": "short"})
        self.assertEqual(bad.status_code, 400)
        dup = self.c.post("/api/v1/auth/register", json={"email": "user@test.com", "password": "password1"})
        self.assertEqual(dup.status_code, 409)

    def test_login(self):
        ok = self.c.post("/api/v1/auth/login", json={"email": "user@test.com", "password": "password1"})
        self.assertEqual(ok.status_code, 200)
        bad = self.c.post("/api/v1/auth/login", json={"email": "user@test.com", "password": "wrongpass"})
        self.assertEqual(bad.status_code, 401)

    def test_create_and_redirect(self):
        r = self.make("https://example.com/redirect-me")
        self.assertEqual(r.status_code, 201)
        code = r.get_json()["code"]
        self.assertEqual(len(code), 7)
        go = self.c.get("/" + code, headers={"Referer": "https://google.com/x"})
        self.assertEqual(go.status_code, 302)
        self.assertEqual(go.headers["Location"], "https://example.com/redirect-me")

    def test_same_url_is_reused(self):
        a = self.make("https://example.com/dup").get_json()
        b = self.make("https://example.com/dup").get_json()
        self.assertEqual(a["code"], b["code"])

    def test_invalid_url_rejected(self):
        self.assertEqual(self.make("not a url").status_code, 400)
        self.assertEqual(self.make("javascript:alert(1)").status_code, 400)

    def test_custom_alias_and_conflict(self):
        self.assertEqual(self.make(alias="my-brand").status_code, 201)
        self.assertEqual(self.make("https://example.com/other", alias="my-brand").status_code, 409)
        self.assertEqual(self.make(alias="api").status_code, 400)
        self.assertEqual(self.make(alias="a b").status_code, 400)

    def test_unknown_and_expired(self):
        self.assertEqual(self.c.get("/doesnotexist").status_code, 404)
        code = self.make("https://example.com/exp", expiresAt="2999-01-01").get_json()["code"]
        with sqlite3.connect(_tmp.name) as conn:
            conn.execute("UPDATE links SET expires_at = 1 WHERE code = ?", (code,))
        shortener.CACHE.clear()
        self.assertEqual(self.c.get("/" + code).status_code, 410)

    def test_stats_and_ownership(self):
        r = self.make("https://example.com/stats-test").get_json()
        self.c.get("/" + r["code"], headers={"Referer": "https://twitter.com/a"})
        stats = self.c.get(f"/api/v1/links/{r['id']}/stats", headers=self.user).get_json()
        self.assertEqual(stats["totalClicks"], 1)
        self.assertEqual(stats["referrers"][0]["name"], "twitter.com")
        other = self.register("other@test.com")
        self.assertEqual(self.c.get(f"/api/v1/links/{r['id']}/stats", headers=other).status_code, 404)
        self.assertEqual(self.c.delete(f"/api/v1/links/{r['id']}", headers=other).status_code, 404)

    def test_delete_link(self):
        r = self.make("https://example.com/delete-me").get_json()
        self.assertEqual(self.c.delete(f"/api/v1/links/{r['id']}", headers=self.user).status_code, 204)
        self.assertEqual(self.c.get("/" + r["code"]).status_code, 404)

    def test_auth_required(self):
        self.assertEqual(self.c.get("/api/v1/links").status_code, 401)

    def test_admin_access(self):
        self.assertEqual(self.c.get("/api/v1/admin/overview", headers=self.user).status_code, 403)
        ov = self.c.get("/api/v1/admin/overview", headers=self.admin)
        self.assertEqual(ov.status_code, 200)
        self.assertIn("allLinks", ov.get_json())

    def test_rate_limit(self):
        shortener.HITS.clear()
        codes = [self.c.get("/nothing-here").status_code for _ in range(302)]
        self.assertEqual(codes[-1], 429)
        shortener.HITS.clear()


if __name__ == "__main__":
    unittest.main()
