"""Mowa i ekran rozdzielone: model oddaje znacznik, kod tnie nadmiar mowy (nie prompt)."""
import re

ZNACZNIK_EKRAN = "[[EKRAN]]"
MAKS_ZNAKOW_MOWY = 220
MAKS_ZDAN_MOWY = 2


def rozdziel(odpowiedz: str) -> dict:
    """Zwraca {'mowa': ..., 'ekran': ...}. Bez znacznika wszystko idzie na ekran, a mowa to pierwsze zdanie."""
    if ZNACZNIK_EKRAN in odpowiedz:
        mowa, ekran = odpowiedz.split(ZNACZNIK_EKRAN, 1)
    else:
        zdania = re.split(r"(?<=[.!?])\s+", odpowiedz.strip())
        mowa, ekran = zdania[0], odpowiedz
    return {"mowa": przytnij_mowe(mowa), "ekran": ekran.strip()}


def przytnij_mowe(tekst: str) -> str:
    tekst = re.sub(r"[*_`#>|]", "", tekst).strip()
    zdania = re.split(r"(?<=[.!?])\s+", tekst)
    tekst = " ".join(zdania[:MAKS_ZDAN_MOWY])
    if len(tekst) > MAKS_ZNAKOW_MOWY:
        tekst = tekst[:MAKS_ZNAKOW_MOWY].rsplit(" ", 1)[0].rstrip(",;:") + "."
    return tekst
