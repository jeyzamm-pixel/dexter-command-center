import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from server import app, auth, buildguard, speech  # noqa: E402

KLUCZ = b"klucz-testowy"
TOKEN = "token-upstream-testowy-1234567890"


# ---------- logowanie ----------
def test_pin_jest_zapisany_jako_skrot_i_sprawdza_sie():
    z = auth.skrot_pinu("2468")
    assert "2468" not in z and z.startswith("pbkdf2$")
    assert auth.sprawdz_pin("2468", z) and not auth.sprawdz_pin("1111", z)


def test_dwa_skroty_tego_samego_pinu_sie_roznia():
    assert auth.skrot_pinu("2468") != auth.skrot_pinu("2468")


def test_sesja_hmac_wazna_podrobiona_i_wygasla():
    c = auth.wystaw_sesje(KLUCZ, teraz=1000)
    assert auth.sesja_wazna(c, KLUCZ, teraz=1001)
    assert not auth.sesja_wazna(c, b"inny-klucz", teraz=1001)
    assert not auth.sesja_wazna(c, KLUCZ, teraz=1000 + auth.TTL_SESJI_S + 1)
    tresc, podpis = c.split(".")
    assert not auth.sesja_wazna(f"{int(tresc) + 99999}.{podpis}", KLUCZ, teraz=1001)
    assert not auth.sesja_wazna("smieci", KLUCZ)


def test_blokada_prob_na_adres_i_globalnie():
    b = auth.BlokadaProb()
    for _ in range(auth.LIMIT_PROB_ADRES):
        b.porazka("1.1.1.1", teraz=100)
    assert b.zablokowany("1.1.1.1", teraz=101)
    assert not b.zablokowany("2.2.2.2", teraz=101)
    assert not b.zablokowany("1.1.1.1", teraz=100 + auth.OKNO_S + 1)   # okno minęło
    g = auth.BlokadaProb()
    for i in range(auth.LIMIT_PROB_GLOBALNIE):
        g.porazka(f"10.0.0.{i}", teraz=100)
    assert g.zablokowany("9.9.9.9", teraz=101)


# ---------- mowa i ekran ----------
def test_znacznik_dzieli_mowe_i_ekran():
    r = speech.rozdziel("Masz dwie decyzje. [[EKRAN]] Szczegóły: pierwsza, druga.")
    assert r == {"mowa": "Masz dwie decyzje.", "ekran": "Szczegóły: pierwsza, druga."}


def test_nadmiar_mowy_tnie_kod():
    dluga = " ".join(f"Zdanie numer {i} jest całkiem długie i nie powinno być czytane na głos." for i in range(6))
    r = speech.rozdziel(dluga + " [[EKRAN]] reszta")
    assert len(r["mowa"]) <= speech.MAKS_ZNAKOW_MOWY + 1
    assert r["mowa"].count(".") <= speech.MAKS_ZDAN_MOWY + 1


def test_mowa_bez_markdownu():
    assert "*" not in speech.rozdziel("**Ważne:** jedno zdanie. [[EKRAN]] x")["mowa"]


def test_brak_znacznika_wszystko_na_ekran():
    r = speech.rozdziel("Pierwsze zdanie. Drugie zdanie.")
    assert r["mowa"] == "Pierwsze zdanie." and r["ekran"] == "Pierwsze zdanie. Drugie zdanie."


# ---------- strażnik paczki ----------
def test_buildguard_odrzuca_klucze_a_przepuszcza_zwykly_kod():
    assert buildguard.skanuj_tekst("const k='sk" + "-abcdefghijklmnop1234';")
    assert buildguard.skanuj_tekst("fetch(u,{headers:{Authorization:'Bearer " + "abcdefghijklmnopqrstuvwxyz'}})")
    assert buildguard.skanuj_tekst("var token = 'abcdefghijklmnopqrstu';")
    assert buildguard.skanuj_tekst("const h='" + "a" * 48 + "'")
    assert buildguard.skanuj_tekst("function ok(){ return 1; }") == []


def test_wlasna_paczka_demo_jest_czysta():
    assert buildguard.skanuj_katalog(ROOT / "demo") == []


# ---------- serwer: sesja, API, tokeny po stronie serwera ----------
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


@pytest.fixture(scope="module")
def serwer():
    s = app.make_server("2468", KLUCZ, TOKEN, 0)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{s.server_address[1]}"
    s.shutdown()


OP = urllib.request.build_opener(NoRedirect)


def zapytaj(url, dane=None, ciasteczko=None):
    r = urllib.request.Request(url, data=dane, headers={"Cookie": ciasteczko} if ciasteczko else {})
    try:
        with OP.open(r) as f:
            return f.status, f.read().decode(), dict(f.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), dict(e.headers)


def zaloguj(serwer):
    st, _, h = zapytaj(serwer + "/login", b"pin=2468")
    assert st == 302
    return h["Set-Cookie"].split(";")[0], h["Set-Cookie"]


def test_bez_sesji_przekierowanie_i_401_na_api(serwer):
    assert zapytaj(serwer + "/")[0] == 302
    assert zapytaj(serwer + "/api/stan")[0] == 401


def test_ciasteczko_sesji_jest_httponly(serwer):
    _, pelne = zaloguj(serwer)
    assert "HttpOnly" in pelne and "SameSite=Strict" in pelne


def test_po_zalogowaniu_widac_panel_i_dane(serwer):
    c, _ = zaloguj(serwer)
    st, body, _ = zapytaj(serwer + "/", ciasteczko=c)
    assert st == 200 and "Kokpit" in body
    st, body, _ = zapytaj(serwer + "/api/stan", ciasteczko=c)
    assert st == 200 and json.loads(body)["firma"] == "Piekarnia Przykładowa"


def test_zly_pin_nie_loguje(serwer):
    st, _, h = zapytaj(serwer + "/login", b"pin=0000")
    assert st == 401 and "Set-Cookie" not in h


def test_token_upstream_nigdy_nie_trafia_do_przegladarki(serwer):
    c, _ = zaloguj(serwer)
    st, body, h = zapytaj(serwer + "/api/dexter", json.dumps({"pytanie": "co dziś?"}).encode(), c)
    assert st == 200
    assert TOKEN not in body and TOKEN not in json.dumps(h)
    r = json.loads(body)
    assert set(r) == {"mowa", "ekran"} and "[[EKRAN]]" not in body


def test_model_bez_tokenu_odmawia():
    with pytest.raises(PermissionError):
        app.upstream_model({}, "x")


def test_blokada_po_wielu_zlych_pinach():
    s = app.make_server("2468", KLUCZ, TOKEN, 0)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{s.server_address[1]}"
    kody = [zapytaj(url + "/login", b"pin=1")[0] for _ in range(auth.LIMIT_PROB_ADRES + 1)]
    assert kody[-1] == 429
    assert zapytaj(url + "/login", b"pin=2468")[0] == 429     # nawet dobry PIN czeka
    s.shutdown()
