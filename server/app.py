"""Minimalny serwer panelu: logowanie PIN-em, sesja, API na danych testowych i proxy do "modelu".

Pokazuje trzy decyzje z produkcji: tokeny tylko po stronie serwera, PIN ze skrótem PBKDF2
i sesją HMAC, mowa oddzielona od ekranu. Dane są wymyślone (demo/fixtures.json).

Uruchom: python -m server.app      (domyślnie http://127.0.0.1:8765, PIN demo: 2468)
"""
import copy
import json
import os
import secrets
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import auth, speech

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = json.loads((ROOT / "demo" / "fixtures.json").read_text(encoding="utf-8"))

LOGIN_HTML = """<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Logowanie</title><body style="font:16px system-ui;background:#f5f8fb;display:grid;place-items:center;height:100vh;margin:0">
<form method="post" action="/login" style="background:#fff;padding:28px;border-radius:14px;border:1px solid #dbe4ec;width:260px">
<b style="font-size:20px">Kokpit</b><p style="color:#58708a">Wpisz PIN.</p>
<input name="pin" type="password" inputmode="numeric" autofocus style="width:100%;padding:10px;font-size:20px;box-sizing:border-box">
<button style="margin-top:12px;width:100%;padding:10px;background:#0A95C9;color:#fff;border:0;border-radius:8px;font-size:16px">Wejdź</button>
<p style="color:#c2410c;margin:10px 0 0">@@BLAD@@</p></form>"""


def upstream_model(naglowki: dict, pytanie: str) -> str:
    """Zastępuje zewnętrzny model. Wymaga tokenu w nagłówku, którego przeglądarka nigdy nie widzi."""
    if not naglowki.get("Authorization", "").startswith("Bearer "):
        raise PermissionError("brak tokenu po stronie serwera")
    return ("Masz dwie decyzje i jedno zadanie na dziś. [[EKRAN]] Decyzje: zatwierdzenie posta na piątek "
            "oraz zamówienie mąki. Zadanie: sprawdzić wynik nocnych testów. Pytałeś: " + pytanie)


def make_server(pin: str, klucz: bytes, token_upstream: str, port: int = 0):
    zapisany = auth.skrot_pinu(pin)
    blokada = auth.BlokadaProb()
    stan = copy.deepcopy(FIXTURES)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _wyslij(self, kod, tresc, typ="text/html; charset=utf-8", naglowki=None):
            dane = tresc.encode("utf-8") if isinstance(tresc, str) else tresc
            self.send_response(kod)
            self.send_header("Content-Type", typ)
            self.send_header("Content-Length", str(len(dane)))
            for k, v in (naglowki or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(dane)

        def _zalogowany(self):
            c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            return "sesja" in c and auth.sesja_wazna(c["sesja"].value, klucz)

        def _json(self):
            return json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0)) or 0) or b"{}")

        def do_GET(self):
            if self.path == "/login":
                return self._wyslij(200, LOGIN_HTML.replace("@@BLAD@@", ""))
            if not self._zalogowany():
                if self.path.startswith("/api/"):
                    return self._wyslij(401, '{"blad":"brak sesji"}', "application/json")
                return self._wyslij(302, "", naglowki={"Location": "/login"})
            if self.path == "/":
                return self._wyslij(200, (ROOT / "demo" / "kokpit.html").read_text(encoding="utf-8"))
            if self.path == "/api/stan":
                return self._wyslij(200, json.dumps(stan, ensure_ascii=False), "application/json")
            self._wyslij(404, "nie ma")

        def do_POST(self):
            adres = self.client_address[0]
            if self.path == "/login":
                if blokada.zablokowany(adres):
                    return self._wyslij(429, LOGIN_HTML.replace("@@BLAD@@", "Za dużo prób. Spróbuj później."))
                dane = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
                wpisany = dict(p.split("=", 1) for p in dane.split("&") if "=" in p).get("pin", "")
                if auth.sprawdz_pin(wpisany, zapisany):
                    cookie = f"sesja={auth.wystaw_sesje(klucz)}; HttpOnly; SameSite=Strict; Path=/"
                    return self._wyslij(302, "", naglowki={"Location": "/", "Set-Cookie": cookie})
                blokada.porazka(adres)
                return self._wyslij(401, LOGIN_HTML.replace("@@BLAD@@", "Zły PIN."))
            if not self._zalogowany():
                return self._wyslij(401, '{"blad":"brak sesji"}', "application/json")
            if self.path == "/api/decyzja":
                d = self._json()
                for x in stan["decyzje"]:
                    if x["id"] == d.get("id"):
                        x["wybor"] = d.get("wybor")
                return self._wyslij(200, '{"ok":true}', "application/json")
            if self.path == "/api/dexter":
                pytanie = self._json().get("pytanie", "")
                # Token dokleja serwer. Do przeglądarki wraca tylko odpowiedź podzielona na mowę i ekran.
                surowa = upstream_model({"Authorization": f"Bearer {token_upstream}"}, pytanie)
                return self._wyslij(200, json.dumps(speech.rozdziel(surowa), ensure_ascii=False), "application/json")
            self._wyslij(404, "nie ma")

    return ThreadingHTTPServer(("127.0.0.1", port), H)


if __name__ == "__main__":
    srv = make_server(os.environ.get("KOKPIT_PIN", "2468"),
                      os.environ.get("KOKPIT_KLUCZ", secrets.token_hex(16)).encode(),
                      os.environ.get("KOKPIT_TOKEN_UPSTREAM", "demo-token-lokalny"), 8765)
    print("Kokpit demo: http://127.0.0.1:8765  (PIN demo: ustaw KOKPIT_PIN, domyślnie 2468)")
    srv.serve_forever()
