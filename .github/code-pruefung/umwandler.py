"""Umwandler nach SARIF 2.1.0 für die Prüfpipeline: pip-audit (JSON) und Pysa (taint-output).

SonarQube liest SARIF über sonar.sarifReportPaths. pip-audit kann kein SARIF, Pysa schreibt sein eigenes
JSON-Zeilen-Format — beides wird hier in SARIF übersetzt. Nur Standardbibliothek.

Teil der Code-Prüfung aus dem Repo Diddy0815/sonarqube (vorlagen/code-pruefung/) — nicht im Ziel-Repo ändern,
sondern dort und neu ausrollen.
"""
from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# Bekannte Pysa-Regeln (Codes aus pyre-check, taint.config/pysa_filters) → deutscher Name
PYSA_REGELN = {
    5001: "Befehls- oder Code-Einschleusung",
    5005: "SQL-Einschleusung",
    5007: "XML External Entities (XXE)",
    5008: "Cross-Site-Scripting (XSS)",
    5011: "Nutzerdaten im Dateisystem",
    5012: "Server-Side Request Forgery (SSRF)",
    5018: "Offene Weiterleitung",
    5029: "Vom Nutzer gesteuerte Antwort-Header",
    6065: "Argument-Einschleusung",
    6066: "Unsichere Deserialisierung",
    6073: "Server-Side Template Injection",
}


# ---------------------------------------------------------------------------------------------------------------
# Schwere
# ---------------------------------------------------------------------------------------------------------------

def _aufrunden(wert: float) -> float:
    """Roundup aus CVSS 3.1 (kleinste Zahl mit einer Nachkommastelle >= wert, ohne Gleitkomma-Ausreißer)."""
    ganz = round(wert * 100_000)
    if ganz % 10_000 == 0:
        return ganz / 100_000
    return (math.floor(ganz / 10_000) + 1) / 10.0


def cvss3_basiswert(vektor: str | None) -> float | None:
    """CVSS-3.x-Basiswert aus einem Vektor wie 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' (→ 9.8).

    Andere Versionen (CVSS:4.0, CVSS:2) oder unvollständige Vektoren → None.
    """
    if not vektor or not re.match(r"^CVSS:3\.[01]/", vektor):
        return None
    teile = dict(t.split(":", 1) for t in vektor.split("/")[1:] if ":" in t)
    try:
        geaendert = teile["S"] == "C"
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[teile["AV"]]
        ac = {"L": 0.77, "H": 0.44}[teile["AC"]]
        pr = {"N": 0.85, "L": 0.68 if geaendert else 0.62, "H": 0.5 if geaendert else 0.27}[teile["PR"]]
        ui = {"N": 0.85, "R": 0.62}[teile["UI"]]
        c, i, a = ({"H": 0.56, "L": 0.22, "N": 0.0}[teile[k]] for k in ("C", "I", "A"))
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    auswirkung = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if geaendert else 6.42 * iss
    if auswirkung <= 0:
        return 0.0
    ausnutzbarkeit = 8.22 * av * ac * pr * ui
    summe = 1.08 * (auswirkung + ausnutzbarkeit) if geaendert else auswirkung + ausnutzbarkeit
    return _aufrunden(min(summe, 10.0))


def stufe(schwere: str | None = None, wert: float | None = None) -> str:
    """SARIF-Level aus Schwere-Text (GHSA: LOW/MODERATE/HIGH/CRITICAL) oder CVSS-Wert; unbekannt → warning."""
    if wert is not None:
        return "error" if wert >= 7.0 else "warning" if wert >= 4.0 else "note"
    text = (schwere or "").upper()
    if text in ("CRITICAL", "HIGH"):
        return "error"
    if text == "LOW":
        return "note"
    return "warning"


def schwere_aus_osv(eintrag: dict) -> tuple[str | None, float | None]:
    """(Schwere-Text, CVSS-Wert) aus einem OSV-Eintrag (api.osv.dev/v1/vulns/<id>) — was davon vorhanden ist."""
    text = ((eintrag.get("database_specific") or {}).get("severity") or None)
    wert = None
    for s in eintrag.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS_V3"):
            wert = cvss3_basiswert(s.get("score"))
            if wert is not None:
                break
    return (text.upper() if isinstance(text, str) else None), wert


def sarif_pfade_normalisieren(daten: dict) -> int:
    """Dateipfade in einem SARIF-Bericht als URI mit '/' (Semgrep schreibt unter Windows 'backend\\x.py', das
    findet SonarQube nicht). Ändert daten an Ort und Stelle; Rückgabe: Anzahl der Ergebnisse."""
    anzahl = 0
    for lauf in daten.get("runs") or []:
        for ergebnis in lauf.get("results") or []:
            anzahl += 1
            for ort in ergebnis.get("locations") or []:
                artefakt = (ort.get("physicalLocation") or {}).get("artifactLocation") or {}
                if isinstance(artefakt.get("uri"), str):
                    artefakt["uri"] = artefakt["uri"].replace("\\", "/").removeprefix("./")
    return anzahl


# ---------------------------------------------------------------------------------------------------------------
# pip-audit
# ---------------------------------------------------------------------------------------------------------------

def paketname(name: str) -> str:
    """Paketname nach PEP 503 vergleichbar machen ('Foo_Bar.baz' → 'foo-bar-baz')."""
    return re.sub(r"[-_.]+", "-", name).lower()


def anforderungs_zeilen(text: str) -> dict[str, int]:
    """Paketname → Zeilennummer (1-basiert) in einer requirements-Datei (erstes Vorkommen)."""
    zeilen: dict[str, int] = {}
    for nr, zeile in enumerate(text.splitlines(), 1):
        zeile = zeile.split(" #", 1)[0].strip()
        if not zeile or zeile.startswith(("#", "-")):
            continue
        treffer = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", zeile)
        if treffer:
            zeilen.setdefault(paketname(treffer.group(1)), nr)
    return zeilen


def _sarif(werkzeug: str, info_url: str, version: str | None, regeln: list[dict], ergebnisse: list[dict]) -> dict:
    treiber = {"name": werkzeug, "informationUri": info_url, "rules": regeln}
    if version:
        treiber["version"] = version
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0",
            "runs": [{"tool": {"driver": treiber}, "results": ergebnisse}]}


def pip_audit_sarif(berichte: Iterable[tuple[str, dict, dict[str, int]]],
                    schwere: dict[str, tuple[str | None, float | None]] | None = None,
                    version: str | None = None) -> dict:
    """SARIF aus pip-audit-Berichten (-f json).

    berichte: je requirements-Datei (Pfad relativ zur Projektwurzel mit '/', pip-audit-JSON, Zeilen aus
    anforderungs_zeilen). schwere: Schwachstellen-ID → (Schwere-Text, CVSS-Wert), soweit bekannt.
    Ort ist die Zeile des Pakets in der requirements-Datei; indirekte Abhängigkeiten stehen auf Zeile 1.
    Regel-ID = Schwachstellen-ID, die Hilfe nennt die behobenen Versionen.
    """
    schwere = schwere or {}
    regeln: dict[str, dict] = {}
    ergebnisse: list[dict] = []
    for datei, bericht, zeilen in berichte:
        # pip-audit nennt dieselbe Schwachstelle manchmal zweimal (gemessen: mcp 1.26.0, je ID doppelt) —
        # zusammenfassen, Aliase und behobene Versionen vereinigen.
        gesammelt: dict[tuple[str, str], dict] = {}
        for paket in bericht.get("dependencies") or []:
            for luecke in paket.get("vulns") or []:
                kennung = luecke.get("id") or "unbekannt"
                eintrag = gesammelt.setdefault((paketname(paket.get("name") or "?"), kennung), {
                    "name": paket.get("name") or "?", "version": paket.get("version") or "?", "id": kennung,
                    "aliases": [], "fix_versions": [], "description": ""})
                for feld in ("aliases", "fix_versions"):
                    eintrag[feld] += [x for x in luecke.get(feld) or [] if x not in eintrag[feld]]
                eintrag["description"] = eintrag["description"] or (luecke.get("description") or "")
        for luecke in gesammelt.values():
            kennung = luecke["id"]
            aliase = [a for a in luecke["aliases"] if a != kennung]
            behoben = luecke["fix_versions"]
            text, wert = schwere.get(kennung, (None, None))
            level = stufe(text, wert)
            name, version_paket = luecke["name"], luecke["version"]
            zeile = zeilen.get(paketname(name))
            if kennung not in regeln:
                beschreibung = (luecke.get("description") or "").strip()
                hilfe = (f"Schwachstelle {kennung}" + (f" ({', '.join(aliase)})" if aliase else "")
                         + f" in {name}. Behoben in: {', '.join(behoben) if behoben else 'noch keiner Version'}."
                         + " Abhängigkeit in der requirements-Datei auf eine behobene Version heben.")
                regel = {"id": kennung, "name": f"Schwachstelle {kennung}",
                         "shortDescription": {"text": f"Bekannte Schwachstelle {kennung} in {name}"[:200]},
                         "fullDescription": {"text": (beschreibung or hilfe)[:4000]},
                         "help": {"text": hilfe},
                         "helpUri": f"https://osv.dev/vulnerability/{kennung}",
                         "defaultConfiguration": {"level": level},
                         "properties": {"tags": ["security", "dependency"]}}
                if wert is not None:
                    regel["properties"]["security-severity"] = f"{wert:.1f}"
                regeln[kennung] = regel
            meldung = (f"{name} {version_paket} hat die bekannte Schwachstelle {kennung}"
                       + (f" ({', '.join(aliase)})" if aliase else "")
                       + (f"; behoben in {', '.join(behoben)}" if behoben else "; noch keine behobene Version")
                       + ("" if zeile else " — indirekte Abhängigkeit (nicht direkt in dieser Datei)") + ".")
            ergebnisse.append({
                "ruleId": kennung, "level": level, "message": {"text": meldung},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": datei},
                                                    "region": {"startLine": zeile or 1}}}],
                "partialFingerprints": {"paket": f"{paketname(name)}:{kennung}"}})
    return _sarif("pip-audit", "https://pypi.org/project/pip-audit/", version, list(regeln.values()), ergebnisse)


# ---------------------------------------------------------------------------------------------------------------
# Pysa
# ---------------------------------------------------------------------------------------------------------------

def pysa_eintraege(zeilen: Iterable[str]) -> list[dict]:
    """Die 'issue'-Einträge aus Pysas taint-output (JSON-Zeilen; Kopfzeile und Modelle werden übergangen)."""
    raus = []
    for zeile in zeilen:
        zeile = zeile.strip()
        if not zeile:
            continue
        try:
            eintrag = json.loads(zeile)
        except ValueError:
            continue
        if isinstance(eintrag, dict) and eintrag.get("kind") == "issue" and isinstance(eintrag.get("data"), dict):
            raus.append(eintrag["data"])
    return raus


def pysa_sarif(befunde: Iterable[dict], version: str | None = None, wurzel: str | None = None) -> dict:
    """SARIF aus Pysa-Befunden (pysa_eintraege). Regel-ID = Pysa-Code; Datei relativ zur Projektwurzel."""
    regeln: dict[str, dict] = {}
    ergebnisse = []
    for b in befunde:
        code = b.get("code")
        kennung = str(code if code is not None else "unbekannt")
        if kennung not in regeln:
            name = PYSA_REGELN.get(code) if isinstance(code, int) else None
            hilfe = ("Daten aus einer vom Nutzer gesteuerten Quelle (z. B. Parameter einer Web-Route) erreichen eine "
                     "gefährliche Senke" + (f" ({name})" if name else "") + ". Eingabe prüfen bzw. bereinigen, bevor "
                     "sie dort ankommt. Gefunden von Pysa (Taint-Analyse von pyre-check), Regel " + kennung + ".")
            # SonarQube übernimmt als Beschreibung nur fullDescription (help allein ergab eine leere Regel).
            regeln[kennung] = {"id": kennung, "name": f"Pysa {kennung}" + (f": {name}" if name else ""),
                               "shortDescription": {"text": f"Pysa-Taint-Fluss {kennung}" + (f" ({name})" if name else "")},
                               "fullDescription": {"text": hilfe},
                               "help": {"text": hilfe},
                               "defaultConfiguration": {"level": "warning"},
                               "properties": {"tags": ["security", "taint"]}}
        datei = str(b.get("filename") or b.get("path") or "").replace("\\", "/")
        if wurzel and datei.startswith(wurzel.rstrip("/") + "/"):
            datei = datei[len(wurzel.rstrip("/")) + 1:]
        datei = datei.removeprefix("./")
        if not datei or datei.startswith("/") or re.match(r"^[A-Za-z]:/", datei):
            continue                          # fremder Code (site-packages, typeshed) — kein Ort im Projekt
        zeile = int(b.get("line") or b.get("callable_line") or 1)
        # Nur die Zeile: Pysas Spaltenangaben passten nicht immer zur Zeile (SonarQube verwarf solche Befunde).
        region: dict = {"startLine": max(zeile, 1)}
        meldung = str(b.get("message") or f"Pysa {kennung}")
        if b.get("callable"):
            meldung += f" (in {b['callable']})"
        ergebnisse.append({"ruleId": kennung, "level": "warning", "message": {"text": meldung[:1000]},
                           "locations": [{"physicalLocation": {"artifactLocation": {"uri": datei}, "region": region}}]})
    return _sarif("pysa", "https://pyre-check.org/docs/pysa-basics/", version, list(regeln.values()), ergebnisse)
