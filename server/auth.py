"""Logowanie PIN-em: skrót PBKDF2, sesja HMAC w ciasteczku HttpOnly, blokada prób.

Tylko biblioteka standardowa. PIN nigdy nie jest zapisany jawnie, a sesja nie wymaga bazy:
ciasteczko niesie czas wygaśnięcia i podpis, który serwer sprawdza kluczem z środowiska.
"""
import base64
import hashlib
import hmac
import os
import time

ITERACJE = 200_000
TTL_SESJI_S = 12 * 3600
LIMIT_PROB_ADRES = 5
LIMIT_PROB_GLOBALNIE = 20
OKNO_S = 300


def skrot_pinu(pin: str, sol: bytes = None) -> str:
    sol = sol or os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", pin.encode(), sol, ITERACJE)
    return f"pbkdf2${ITERACJE}${base64.b64encode(sol).decode()}${base64.b64encode(h).decode()}"


def sprawdz_pin(pin: str, zapisany: str) -> bool:
    _, iteracje, sol, h = zapisany.split("$")
    obliczony = hashlib.pbkdf2_hmac("sha256", pin.encode(), base64.b64decode(sol), int(iteracje))
    return hmac.compare_digest(obliczony, base64.b64decode(h))


def wystaw_sesje(klucz: bytes, teraz: float = None) -> str:
    wygasa = int((teraz or time.time()) + TTL_SESJI_S)
    tresc = str(wygasa)
    podpis = hmac.new(klucz, tresc.encode(), hashlib.sha256).hexdigest()
    return f"{tresc}.{podpis}"


def sesja_wazna(ciasteczko: str, klucz: bytes, teraz: float = None) -> bool:
    try:
        tresc, podpis = ciasteczko.split(".")
        oczekiwany = hmac.new(klucz, tresc.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(podpis, oczekiwany) and int(tresc) > (teraz or time.time())
    except (ValueError, AttributeError):
        return False


class BlokadaProb:
    """Limit nieudanych prób na adres i globalnie (przed zgadywaniem PIN-u z wielu adresów)."""

    def __init__(self):
        self.proby = []          # (czas, adres)

    def _swieze(self, teraz):
        self.proby = [(t, a) for t, a in self.proby if teraz - t < OKNO_S]

    def zablokowany(self, adres: str, teraz: float = None) -> bool:
        teraz = teraz or time.time()
        self._swieze(teraz)
        return (sum(a == adres for _, a in self.proby) >= LIMIT_PROB_ADRES
                or len(self.proby) >= LIMIT_PROB_GLOBALNIE)

    def porazka(self, adres: str, teraz: float = None):
        self.proby.append((teraz or time.time(), adres))
