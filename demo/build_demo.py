"""Buduje demo/kokpit.html (dane testowe wbudowane) i robi zrzuty komputer + telefon.

Uruchom: python demo/build_demo.py     (zrzuty: playwright install chromium)
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
D = ROOT / "demo"


def build():
    fx = json.loads((D / "fixtures.json").read_text(encoding="utf-8"))
    html = (D / "kokpit.template.html").read_text(encoding="utf-8")
    html = html.replace("/*FIXTURE*/null", json.dumps(fx, ensure_ascii=False))
    (D / "kokpit.html").write_text(html, encoding="utf-8")
    return D / "kokpit.html"


if __name__ == "__main__":
    out = build()
    print("zapisano", out.relative_to(ROOT))
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            b = p.chromium.launch()
            (ROOT / "screenshots").mkdir(exist_ok=True)
            pg = b.new_page(viewport={"width": 1440, "height": 860})
            pg.goto(out.as_uri())
            pg.click('#decyzje .dec:nth-of-type(2) button[data-wybor="tak"]')
            pg.screenshot(path=str(ROOT / "screenshots" / "kokpit-komputer.png"), full_page=True)
            pg = b.new_page(viewport={"width": 412, "height": 860}, is_mobile=True, has_touch=True)
            pg.goto(out.as_uri())
            pg.screenshot(path=str(ROOT / "screenshots" / "kokpit-telefon.png"), full_page=True)
            b.close()
        print("zrzuty ok")
    except ImportError:
        print("brak playwright: pominięto zrzuty")
