"""Strażnik paczki frontendu: odrzuca build, w którym jest cokolwiek podobnego do klucza.

Użycie: python -m server.buildguard demo   (kod wyjścia 1, gdy coś znajdzie)
"""
import re
import sys
from pathlib import Path

WZORCE = {
    "klucz API": re.compile(r"\b(sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_\-]{30,}|AKIA[0-9A-Z]{12,})"),
    "nagłówek Bearer": re.compile(r"Bearer\s+[A-Za-z0-9._\-]{20,}"),
    "przypisanie sekretu": re.compile(r"(?i)\b(token|secret|api[_-]?key|password)\b\s*[:=]\s*['\"][^'\"]{12,}['\"]"),
    "długi ciąg hex": re.compile(r"\b[0-9a-f]{40,}\b"),
}


def skanuj_tekst(tekst: str) -> list:
    return [nazwa for nazwa, w in WZORCE.items() if w.search(tekst)]


def skanuj_katalog(katalog) -> list:
    wynik = []
    for p in Path(katalog).rglob("*"):
        if p.is_file() and p.suffix in {".html", ".js", ".css", ".json", ".map"}:
            for nazwa in skanuj_tekst(p.read_text(encoding="utf-8", errors="ignore")):
                wynik.append((str(p), nazwa))
    return wynik


if __name__ == "__main__":
    znaleziska = skanuj_katalog(sys.argv[1] if len(sys.argv) > 1 else "demo")
    for sciezka, co in znaleziska:
        print("ODRZUCONO:", sciezka, co)
    sys.exit(1 if znaleziska else 0)
