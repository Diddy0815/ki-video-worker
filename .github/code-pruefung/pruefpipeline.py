"""Prüfpipeline der Code-Prüfung: Zusatzwerkzeuge → SonarQube-Scanner — ein Ablauf für alle Wege.

Aufgerufen von
  - der GitHub Action „Code-Prüfung“ (.github/workflows/code-pruefung.yml; Linux, im Profil web mit Pysa),
  - erstscan.py im Repo Diddy0815/sonarqube (Windows; der gepushte Stand per git archive),
  - scan-lokal.ps1 im Repo Diddy0815/sonarqube (Windows; der Arbeitsordner inkl. ungepushter Änderungen,
    in ein eigenes Sonar-Projekt „<schlüssel>-lokal“, damit der gemeinsame Stand nie überschrieben wird).

Ablauf (streng nacheinander):
  1. Bandit      → bandit.json      → sonar.python.bandit.reportPaths
  2. Semgrep CE  → semgrep.sarif    → sonar.sarifReportPaths  (p/python, p/security-audit, p/secrets; ohne Konto)
  3. pip-audit   → pip-audit.sarif  (eigener Umwandler; nur wenn es requirements*.txt gibt)
  4. Pysa        → pysa.sarif       (nur Profil web und nur unter Linux — Versuch, darf den Lauf nie scheitern lassen)
  5. pysonar mit allen Berichten; mit --warten bis SonarQube die Analyse verarbeitet hat.
Welche Werkzeuge in welcher Version wie gelaufen sind, bekommt die Analyse als Eigenschaft sonar.analysis.werkzeuge
mit (werkzeuge_angabe()) — SonarQube reicht sie im Webhook an die Verwaltung weiter (Prüfbescheinigung).
Fehlt ein Werkzeug oder scheitert es, geht es mit Hinweis weiter — über Erfolg entscheidet nur der Scanner. Damit
SonarQube dessen Befunde dabei nicht als behoben schließt (es schließt jeden externen Befund, der im Bericht fehlt),
schreibt die Pipeline die offenen Befunde dieses Werkzeugs aus SonarQube unverändert fort, bis es wieder läuft
(fortschreiben()). Gelingt das nicht, wird nichts hochgeladen.
Testcode (TEST_MUSTER) prüfen Bandit und Semgrep nicht; SonarQube führt ihn als Test (sonar.tests).
Mit --zeitbudget teilt sich die Pipeline die Zeit ein (Action: Job-Zeitlimit) — die Werkzeuge bekommen höchstens so
viel, dass Scanner und Verarbeitung noch Platz haben.

Aufruf:
  python pruefpipeline.py --key verwaltung --name Verwaltung --profil web --warten --zeitbudget 2400  (Action)
  python pruefpipeline.py --quelle <ordner> --key k --revision <sha> --ohne-scm    (erstscan.py)
  python pruefpipeline.py --lokal --quelle <ordner> --warten                       (scan-lokal.ps1)
Token: SONAR_TOKEN (Action) oder SONAR_SCAN_TOKEN, sonst per ssh vom Server (nur am PC); wird nie ausgegeben und
geht nur an den Scanner, nie an die Werkzeuge (pip-audit führt beim Auflösen Build-Code fremder Pakete aus).
Rückgabe: 0 = gescannt, 1 = Scanner oder SonarQube-Verarbeitung gescheitert, 2 = Abbruch vor dem Scan.

Nur Standardbibliothek (+ die Werkzeuge selbst). Teil der Code-Prüfung aus dem Repo Diddy0815/sonarqube
(vorlagen/code-pruefung/) — nicht im Ziel-Repo ändern, sondern dort und neu ausrollen (ausrollen.py).
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

HIER = Path(__file__).resolve().parent
if str(HIER) not in sys.path:
    sys.path.insert(0, str(HIER))
import umwandler  # noqa: E402

SONAR_URL = "https://sonar.816.at"
SERVER = "root@81.173.84.11"
# SonarQube schläft am VPS im Bedarfsbetrieb (spart 2,5 GB). Die Verwaltung reicht den Weckruf an die Server-Wache
# weiter; ausweisen darf sich der Lauf mit dem Scanner-Token (die Verwaltung kennt ihn als SONAR_WECK_TOKEN).
WECKEN_URL = os.environ.get("SONAR_WECKEN_URL", "https://verwaltung.816.at/api/sonar/wecken")
TOKEN_DATEI = "/opt/sonarqube/scanner.token"
LOKAL_ENDUNG = "-lokal"
PROFILE = ("desktop", "web")
PYSA_MODELLE = HIER / "pysa"

# Was SonarQube nicht analysiert: fremder Code, Bau-Ergebnisse, Testdaten, Doku-Ordner im Wurzelordner (Änderungen
# dort lösen keinen Scan aus) und die ausgerollte Pipeline selbst.
AUSSCHLUESSE = (
    "**/venv/**", "**/.venv/**", "**/node_modules/**", "**/lib/**", "**/libs/**", "**/vendor/**", "**/third_party/**",
    "**/dist/**", "**/build/**", "**/build_*/**", "**/dist_*/**", "**/_internal/**", "**/__pycache__/**",
    "**/*.min.*", "**/*.bundle.*", "**/*.spec", "**/testdaten/**", "**/test_daten/**", "**/testdata/**",
    "**/test_data/**", "docs/**", "wiki/**", ".github/code-pruefung/**", "**/.pyre/**",
)
# Testcode: SonarQube führt ihn als Test (sonar.tests), Bandit und Semgrep lassen ihn aus.
TEST_MUSTER = (
    "**/tests/**", "**/test/**", "**/test_*.py", "**/*_test.py", "**/conftest.py", "**/pruefe_*.py", "**/*.test.js",
)
# Eigene Ausschlüsse eines Projekts (Datei im Projekt-Wurzelordner): ein Sonar-Muster je Zeile, '#' = Kommentar —
# z. B. eine mitgeführte Wissensquelle, die nicht ausgeliefert wird. Wirken wie AUSSCHLUESSE (ausschluesse()).
AUSSCHLUSS_DATEI = ".code-pruefung-ausschluesse"

# Bandit-Prüfungen, die nicht laufen — Begründung je Prüfung (README, Abschnitt „Zusatzwerkzeuge“).
# 1) Doppelt: deckt eine im Standardprofil aktive SonarQube-Regel ab (geprüft am 06.10.2026, Community Build 26.9).
# 2) Nur Hinweis: meldet ein Muster ohne konkreten Fehler (jeder subprocess-Import, jedes urlopen …).
BANDIT_UEBERSPRINGEN = {
    "B101": "Hinweis: assert — in Tests gewollt, im Programmcode bewusste Plausibilitätsprüfung",
    "B103": "doppelt: python:S2612 (Dateirechte für alle)",
    "B104": "doppelt: python:S8392 (Server lauscht auf allen Schnittstellen)",
    "B105": "doppelt: python:S2068/S6418/S6437 (fest eingetragene Zugangsdaten)",
    "B106": "doppelt: python:S2068/S6418/S6437 (fest eingetragene Zugangsdaten)",
    "B107": "doppelt: python:S2068/S6418/S6437 (fest eingetragene Zugangsdaten)",
    "B108": "doppelt: python:S5443 (Temp-Dateien in allgemein beschreibbaren Ordnern)",
    "B110": "Hinweis: try/except/pass — Code-Qualität, kein Sicherheitsbefund (Sonar: python:S108, S5754)",
    "B112": "Hinweis: try/except/continue — Code-Qualität, kein Sicherheitsbefund",
    "B201": "doppelt: python:S4507 (Debug-Modus in Produktion)",
    "B303": "doppelt: python:S4790 (schwache Hash-Verfahren)",
    "B304": "doppelt: python:S5547 (schwache Verschlüsselung)",
    "B305": "doppelt: python:S5542 (unsicherer Verschlüsselungsmodus)",
    "B306": "doppelt: python:S5445 (unsichere Temp-Datei mktemp)",
    "B310": "Hinweis: meldet jedes urlopen — Gefahr nur bei file://-Adressen aus Nutzereingaben (Semgrep/Pysa)",
    "B311": "doppelt: python:S2245 (Zufallszahlen für Sicherheitszwecke)",
    "B313": "doppelt: python:S2755 (XXE); Pythons xml-Module laden seit 3.7.1 keine externen Entitäten",
    "B314": "doppelt: python:S2755 (XXE)",
    "B315": "doppelt: python:S2755 (XXE)",
    "B316": "doppelt: python:S2755 (XXE)",
    "B317": "doppelt: python:S2755 (XXE)",
    "B318": "doppelt: python:S2755 (XXE)",
    "B319": "doppelt: python:S2755 (XXE)",
    "B320": "doppelt: python:S2755 (XXE)",
    "B324": "doppelt: python:S4790 (schwache Hash-Verfahren in hashlib)",
    "B403": "Hinweis: reiner Import von pickle — der Aufruf selbst (B301) wird weiter geprüft",
    "B404": "Hinweis: reiner Import von subprocess",
    "B405": "Hinweis: reiner Import eines xml-Moduls (siehe B313–B320)",
    "B406": "Hinweis: reiner Import eines xml-Moduls",
    "B407": "Hinweis: reiner Import eines xml-Moduls",
    "B408": "Hinweis: reiner Import eines xml-Moduls",
    "B409": "Hinweis: reiner Import eines xml-Moduls",
    "B410": "Hinweis: reiner Import von lxml (Konfiguration prüft python:S2755)",
    "B411": "Hinweis: reiner Import von xmlrpc",
    "B501": "doppelt: python:S4830 (Zertifikatsprüfung abgeschaltet)",
    "B502": "doppelt: python:S4423 (schwache SSL/TLS-Version)",
    "B503": "doppelt: python:S4423 (schwache SSL/TLS-Version)",
    "B504": "doppelt: python:S4423 (schwache SSL/TLS-Version)",
    "B505": "doppelt: python:S4426 (zu kurzer Schlüssel)",
    "B603": "Hinweis: subprocess ohne Shell — nur „auf Nutzereingaben prüfen“, kein Befund",
    "B606": "Hinweis: Prozessstart ohne Shell — kein Befund",
    "B607": "Hinweis: Programm ohne vollen Pfad (git, python …) — gewollt, kein Befund",
    "B608": "doppelt: python:S2077 (SQL-Abfrage aus Zeichenketten zusammengesetzt)",
    "B614": "doppelt: python:S6985 (torch.load ohne Einschränkung)",
    "B701": "doppelt: python:S5247 (Auto-Escaping in Jinja2 abgeschaltet)",
}
SEMGREP_REGELSAETZE = ("p/python", "p/security-audit", "p/secrets")
# Semgrep-Regeln, die nicht laufen — aus demselben Grund wie bei Bandit: doppelt mit einer aktiven SonarQube-Regel,
# doppelt mit einer Bandit-Prüfung, die weiterläuft, oder reiner Hinweis ohne Befund.
_SG = "python.lang.security."
SEMGREP_UEBERSPRINGEN = {
    **dict.fromkeys((
        _SG + "insecure-hash-algorithms-md5.insecure-hash-algorithm-md5",
        _SG + "insecure-hash-algorithms.insecure-hash-algorithm-sha1",
        _SG + "insecure-hash-function.insecure-hash-function",
        _SG + "audit.md5-used-as-password.md5-used-as-password",
        "python.cryptography.security.insecure-hash-algorithms-md5.insecure-hash-algorithm-md5",
        "python.cryptography.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1",
        "python.pycryptodome.security.insecure-hash-algorithm-md2.insecure-hash-algorithm-md2",
        "python.pycryptodome.security.insecure-hash-algorithm-md4.insecure-hash-algorithm-md4",
        "python.pycryptodome.security.insecure-hash-algorithm-md5.insecure-hash-algorithm-md5",
        "python.pycryptodome.security.insecure-hash-algorithm.insecure-hash-algorithm-sha1"),
        "doppelt: python:S4790 (schwache Hash-Verfahren)"),
    **dict.fromkeys((
        "python.cryptography.security.insecure-cipher-algorithms-arc4.insecure-cipher-algorithm-arc4",
        "python.cryptography.security.insecure-cipher-algorithms-blowfish.insecure-cipher-algorithm-blowfish",
        "python.cryptography.security.insecure-cipher-algorithms.insecure-cipher-algorithm-idea",
        "python.cryptography.security.insecure-cipher-mode-ecb.insecure-cipher-mode-ecb",
        "python.pycryptodome.security.insecure-cipher-algorithm-blowfish.insecure-cipher-algorithm-blowfish",
        "python.pycryptodome.security.insecure-cipher-algorithm-des.insecure-cipher-algorithm-des",
        "python.pycryptodome.security.insecure-cipher-algorithm-rc2.insecure-cipher-algorithm-rc2",
        "python.pycryptodome.security.insecure-cipher-algorithm-rc4.insecure-cipher-algorithm-rc4"),
        "doppelt: python:S5547/S5542 (schwache Verschlüsselung bzw. Modus)"),
    **dict.fromkeys((
        "python.cryptography.security.insufficient-dsa-key-size.insufficient-dsa-key-size",
        "python.cryptography.security.insufficient-ec-key-size.insufficient-ec-key-size",
        "python.cryptography.security.insufficient-rsa-key-size.insufficient-rsa-key-size",
        "python.pycryptodome.security.insufficient-dsa-key-size.insufficient-dsa-key-size",
        "python.pycryptodome.security.insufficient-rsa-key-size.insufficient-rsa-key-size"),
        "doppelt: python:S4426 (zu kurzer Schlüssel)"),
    **dict.fromkeys((
        _SG + "audit.network.disabled-cert-validation.disabled-cert-validation",
        _SG + "unverified-ssl-context.unverified-ssl-context",
        "python.requests.security.disabled-cert-validation.disabled-cert-validation"),
        "doppelt: python:S4830 (Zertifikatsprüfung abgeschaltet)"),
    **dict.fromkeys((
        _SG + "audit.insecure-transport.requests.request-with-http.request-with-http",
        _SG + "audit.insecure-transport.requests.request-session-with-http.request-session-with-http",
        _SG + "audit.insecure-transport.requests.request-session-http-in-with-context."
              "request-session-http-in-with-context",
        _SG + "audit.network.http-not-https-connection.http-not-https-connection"),
        "doppelt: python:S5332 (unverschlüsseltes http)"),
    _SG + "audit.weak-ssl-version.weak-ssl-version": "doppelt: python:S4423 (schwache SSL/TLS-Version)",
    _SG + "audit.insecure-file-permissions.insecure-file-permissions": "doppelt: python:S2612 (Dateirechte)",
    _SG + "audit.network.bind.avoid-bind-to-all-interfaces": "doppelt: python:S8392 (alle Schnittstellen)",
    _SG + "audit.hardcoded-password-default-argument.hardcoded-password-default-argument":
        "doppelt: python:S2068 (fest eingetragene Zugangsdaten)",
    "python.flask.security.audit.debug-enabled.debug-enabled": "doppelt: python:S4507 (Debug-Modus)",
    "python.jinja2.security.audit.autoescape-disabled-false.incorrect-autoescape-disabled":
        "doppelt: python:S5247 (Auto-Escaping aus)",
    _SG + "audit.eval-detected.eval-detected": "doppelt: Bandit B307 (eval)",
    _SG + "audit.exec-detected.exec-detected": "doppelt: Bandit B102 (exec)",
    _SG + "audit.subprocess-shell-true.subprocess-shell-true": "doppelt: Bandit B602 (subprocess mit shell=True)",
    _SG + "audit.marshal.marshal-usage": "doppelt: Bandit B302 (marshal)",
    _SG + "audit.telnetlib.telnetlib": "doppelt: Bandit B312 (telnetlib)",
    _SG + "deserialization.pickle.avoid-pickle": "doppelt: Bandit B301 (pickle)",
    _SG + "deserialization.avoid-pyyaml-load.avoid-pyyaml-load": "doppelt: Bandit B506 (yaml.load)",
    _SG + "audit.paramiko.paramiko-exec-command.paramiko-exec-command": "doppelt: Bandit B601 (paramiko exec)",
    _SG + "audit.paramiko-implicit-trust-host-key.paramiko-implicit-trust-host-key":
        "doppelt: Bandit B507 (SSH-Hostschlüssel ungeprüft)",
    _SG + "audit.mako-templates-detected.mako-templates-detected": "doppelt: Bandit B702 (Mako)",
    _SG + "audit.system-wildcard-detected.system-wildcard-detected": "doppelt: Bandit B609 (Platzhalter in Befehl)",
    _SG + "audit.logging.listeneval.listen-eval": "doppelt: Bandit B612 (logging.config.listen)",
    _SG + "audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected":
        "Hinweis: meldet jedes urlopen mit variabler Adresse (wie Bandit B310)",
    _SG + "audit.httpsconnection-detected.httpsconnection-detected": "Hinweis: jede HTTPSConnection",
    _SG + "use-defused-xml.use-defused-xml": "Hinweis: reiner xml-Import (wie Bandit B405–B411)",
    _SG + "use-defused-xml-parse.use-defused-xml-parse": "doppelt: python:S2755 (XXE)",
    _SG + "use-defused-xmlrpc.use-defused-xmlrpc": "Hinweis: reiner xmlrpc-Import (wie Bandit B411)",
}
GRENZE = {"bandit": 600, "semgrep": 900, "pip-audit": 600, "pysa": 1500, "scanner": 1800, "server": 1800}
# Mit --zeitbudget: so viel bleibt für Scanner und Verarbeitung frei; weniger Restzeit als WERKZEUG_MINDESTENS → das
# Werkzeug läuft nicht (seine Befunde werden fortgeschrieben).
RESERVE_SCANNER = 600
WERKZEUG_MINDESTENS = 30
OSV_URL = "https://api.osv.dev/v1/vulns/"
OSV_HOECHSTENS = 60
OSV_GESAMT = 120                      # Sekunden für alle Schwere-Abfragen bei api.osv.dev zusammen
# Semgrep lässt größere Dateien aus (--max-target-bytes) — still, mit Exit 0. Darum meldet die Pipeline sie selbst
# (Hinweis, „ungeprüft“). Nicht höher: gemessen am 06.10.2026 (Semgrep 1.179, alle drei Regelsätze, eine Datei)
# brauchte Aufgabenplaner_V5_2.py (1,07 MB) 3:38 Minuten und brach trotzdem nach 3 Regel-Zeitüberschreitungen ab;
# ProjektmanagerPro.py (3,3 MB) war nach 15 Minuten nicht fertig — der ganze Semgrep-Schritt wäre gescheitert.
# Diese Dateien prüfen SonarQube selbst und Bandit (ohne Größengrenze).
SEMGREP_HOECHSTENS_BYTES = 1_000_000
SEMGREP_QUELLTEXT = (".py", ".pyw", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".html", ".htm", ".vue", ".sh",
                     ".ps1", ".sql")
# Reine Windows-Pakete ohne Linux-Ausgabe: pip kann sie in der Action (Linux) nicht auflösen — pip-audit scheiterte
# dann an der ganzen Datei. Unter Linux bekommen sie die Markierung ; sys_platform == "win32" (pip überspringt sie).
WINDOWS_PAKETE = frozenset({"pywin32", "pypiwin32", "pywinpty", "pywinauto", "windows-curses", "wmi", "winshell",
                            "win10toast"})
TOKEN_VARIABLEN = ("SONAR_TOKEN", "SONAR_SCAN_TOKEN")
WERKZEUGE = ("bandit", "semgrep", "pip-audit", "pysa")
# Analyse-Eigenschaft mit den Werkzeugen dieses Laufs: SonarQube speichert sonar.analysis.* je Analyse und gibt sie im
# Webhook unter "properties" weiter. Die Verwaltung zeigt sie in Prüfbescheinigung und Programmbericht.
EIGENSCHAFT_WERKZEUGE = "sonar.analysis.werkzeuge"


# ---------------------------------------------------------------------------------------------------------------
# Kleinigkeiten
# ---------------------------------------------------------------------------------------------------------------

def konsole_utf8() -> None:
    """Umlaute auch bei umgeleiteter Ausgabe sauber (Windows nimmt sonst cp1252)."""
    for strom in (sys.stdout, sys.stderr):
        try:
            strom.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def in_actions() -> bool:
    return os.environ.get("GITHUB_ACTIONS") == "true"


def hinweis(text: str) -> None:
    """Hinweis ausgeben — in GitHub Actions zusätzlich als Warnung am Lauf."""
    print(f"  Hinweis: {text}", flush=True)
    if in_actions():
        print(f"::warning title=Prüfpipeline::{text}", flush=True)


def dauer(sekunden: float) -> str:
    """142.3 → '2:22' bzw. 3725 → '1:02:05'."""
    s = int(round(sekunden))
    stunden, rest = divmod(s, 3600)
    minuten, s = divmod(rest, 60)
    return f"{stunden}:{minuten:02d}:{s:02d}" if stunden else f"{minuten}:{s:02d}"


def sonar_schluessel(ordner: str) -> str:
    """Sonar-Projektschlüssel aus dem Ordnernamen der Verwaltung (Sonderzeichen → _, reine Ziffern mit p_ davor)."""
    schluessel = re.sub(r"[^A-Za-z0-9_.:-]", "_", ordner)
    return "p_" + schluessel if schluessel.isdigit() else schluessel


def _muster_rumpf(muster: str) -> str:
    """Sonar-Muster (Ant-Stil: **, *, ?) als Regex-Rumpf für Pfade mit '/' relativ zur Projektwurzel."""
    rumpf, i = "", 0
    while i < len(muster):
        if muster.startswith("**/", i):
            rumpf, i = rumpf + "(?:.*/)?", i + 3
        elif muster.startswith("/**", i) and i + 3 == len(muster):
            rumpf, i = rumpf + "/.*", i + 3
        elif muster.startswith("**", i):
            rumpf, i = rumpf + ".*", i + 2
        elif muster[i] == "*":
            rumpf, i = rumpf + "[^/]*", i + 1
        elif muster[i] == "?":
            rumpf, i = rumpf + "[^/]", i + 1
        else:
            rumpf, i = rumpf + re.escape(muster[i]), i + 1
    return rumpf


_MUSTER_CACHE: dict[tuple[str, ...], re.Pattern] = {}


def ausgeschlossen(relativ: str, muster: tuple[str, ...] = AUSSCHLUESSE + TEST_MUSTER) -> bool:
    """Trifft eines der Sonar-Muster auf den Pfad (relativ zur Projektwurzel) zu?"""
    regex = _MUSTER_CACHE.get(muster)
    if regex is None:
        regex = _MUSTER_CACHE[muster] = re.compile("^(?:" + "|".join(_muster_rumpf(m) for m in muster) + ")$")
    return bool(regex.match(relativ.replace("\\", "/").removeprefix("./")))


def projekt_ausschluesse(quelle: Path | None) -> tuple[str, ...]:
    """Die Muster aus AUSSCHLUSS_DATEI im Wurzelordner von quelle (fehlt die Datei: keine). Je Zeile ein Sonar-Muster
    relativ zur Projektwurzel; Leerzeilen und '#'-Kommentare zählen nicht, Backslash wird '/', führendes './' bzw.
    '/' fällt weg, ein Ordner mit '/' am Ende wird zu 'ordner/**'. Zeilen mit ',' (Trenner in sonar.exclusions) oder
    '..' bleiben draußen."""
    if quelle is None:
        return ()
    try:
        text = (Path(quelle) / AUSSCHLUSS_DATEI).read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return ()
    raus: list[str] = []
    for zeile in text.splitlines():
        muster = zeile.split("#", 1)[0].strip().replace("\\", "/")
        while muster.startswith(("./", "/")):
            muster = muster.removeprefix(".").removeprefix("/")
        if muster.endswith("/"):
            muster += "**"
        if muster and "," not in muster and ".." not in muster.split("/") and muster not in raus:
            raus.append(muster)
    return tuple(raus)


def ausschluesse(quelle: Path | None = None) -> tuple[str, ...]:
    """Was in diesem Projekt nicht geprüft wird: AUSSCHLUESSE plus die eigenen Muster des Projekts (ohne Testcode)."""
    return AUSSCHLUESSE + tuple(m for m in projekt_ausschluesse(quelle) if m not in AUSSCHLUESSE)


def _projektdateien(quelle: Path):
    """(Pfad relativ zur Projektwurzel mit '/', Pfad) aller Dateien ohne .git, ausgeschlossene Ordner und Testcode."""
    muster = ausschluesse(quelle) + TEST_MUSTER
    for wurzel, ordner, dateien in os.walk(quelle):
        rel = Path(wurzel).relative_to(quelle).as_posix()
        rel = "" if rel == "." else rel + "/"
        ordner[:] = [o for o in ordner if o != ".git" and not ausgeschlossen(f"{rel}{o}/_", muster)]
        for datei in dateien:
            if not ausgeschlossen(rel + datei, muster):
                yield rel + datei, Path(wurzel) / datei


def dateien_finden(quelle: Path, name_muster: str) -> list[Path]:
    """Dateien mit diesem Namensmuster (fnmatch) unterhalb von quelle, ohne ausgeschlossene Ordner und Testcode."""
    import fnmatch
    return sorted(p for rel, p in _projektdateien(quelle) if fnmatch.fnmatch(p.name.lower(), name_muster))


def zu_gross_fuer_semgrep(quelle: Path, grenze: int = SEMGREP_HOECHSTENS_BYTES) -> list[str]:
    """Quelltext-Dateien, die Semgrep wegen --max-target-bytes auslässt (Pfad relativ zur Projektwurzel)."""
    raus = []
    for rel, p in _projektdateien(quelle):
        try:
            if p.suffix.lower() in SEMGREP_QUELLTEXT and p.stat().st_size > grenze:
                raus.append(rel)
        except OSError:
            continue
    return sorted(raus)


def bandit_ausschluesse(quelle: Path | None = None) -> list[str]:
    """Muster für bandit -x (fnmatch auf Pfade wie './backend/x.py'); mit quelle samt eigenen Projekt-Ausschlüssen."""
    raus = ["*/.git/*"]
    for m in ausschluesse(quelle) + TEST_MUSTER:
        m = "*/" + m[3:] if m.startswith("**/") else "./" + m
        raus.append(m.replace("/**", "/*"))
    return raus


def pyre_ausschluesse(quelle: Path) -> list[str]:
    """Regex-Liste für "exclude" in .pyre_configuration (Pyre vergleicht mit absoluten Pfaden)."""
    wurzel = re.escape(quelle.resolve().as_posix().rstrip("/"))
    return [f"^{wurzel}/{_muster_rumpf(m)}$" for m in ausschluesse(quelle) + TEST_MUSTER]


def sonar_eigenschaften(bandit: list[str] | None = None, sarif: list[str] | None = None,
                        revision: str | None = None, ohne_scm: bool = False, werkzeuge: str | None = None,
                        raus: tuple[str, ...] = AUSSCHLUESSE) -> list[str]:
    """Die -Dsonar.…-Argumente des Scanners: Quellen, Tests, Ausschlüsse, Berichte der Zusatzwerkzeuge und (werkzeuge)
    die Angabe, welche Werkzeuge wie gelaufen sind (EIGENSCHAFT_WERKZEUGE, siehe werkzeuge_angabe).
    raus: die Ausschlüsse dieses Projekts (ausschluesse(quelle)), Standard AUSSCHLUESSE.

    Quellen und Tests liegen beide unter '.'; was Test ist, steht in TEST_MUSTER — dieselben Muster stehen darum
    auch in sonar.exclusions (sonst: „can't be indexed twice“), fremder Code ist in beiden ausgeschlossen.
    """
    eigen = [
        "-Dsonar.sources=.",
        "-Dsonar.tests=.",
        "-Dsonar.test.inclusions=" + ",".join(TEST_MUSTER),
        "-Dsonar.exclusions=" + ",".join(raus + TEST_MUSTER),
        "-Dsonar.test.exclusions=" + ",".join(raus),
        "-Dsonar.sourceEncoding=UTF-8",
        "-Dsonar.python.version=3.12",
    ]
    if bandit:
        eigen.append("-Dsonar.python.bandit.reportPaths=" + ",".join(bandit))
    if sarif:
        eigen.append("-Dsonar.sarifReportPaths=" + ",".join(sarif))
    if ohne_scm:
        eigen.append("-Dsonar.scm.disabled=true")       # kein .git (git archive) — den Commit gibt die Revision mit
    if revision:
        eigen.append(f"-Dsonar.scm.revision={revision}")
    if werkzeuge:
        eigen.append(f"-D{EIGENSCHAFT_WERKZEUGE}={werkzeuge}")
    return eigen


# ---------------------------------------------------------------------------------------------------------------
# Werkzeuge
# ---------------------------------------------------------------------------------------------------------------

@dataclass
class Schritt:
    name: str
    status: str = "übersprungen"      # ok | übersprungen | fehler
    dauer: float = 0.0
    befunde: int | None = None
    hinweis: str = ""
    bericht: str | None = None
    # Deckt das Ergebnis alles ab, was das Werkzeug hier prüfen würde? Nein → seine offenen Befunde in SonarQube
    # werden fortgeschrieben (fortschreiben), sonst schlösse die Analyse sie als behoben. „Nichts zu prüfen“ (keine
    # requirements*.txt, Pysa im Profil desktop) zählt als vollständig.
    vollstaendig: bool = False
    # Nur diese Dateien (relativ zur Projektwurzel) sind nicht geprüft — leer heißt: gar nichts (bei unvollständig)
    ungeprueft: list[str] = field(default_factory=list)
    version: str | None = None        # Version des Werkzeugs (für sonar.analysis.werkzeuge), None = unbekannt


def werkzeug_status(kennung: str, s: Schritt) -> str:
    """Status eines Werkzeugs in diesem Lauf, wie er in sonar.analysis.werkzeuge steht:
    ok              vollständig gelaufen (Pysa: „Versuch“ — gelaufen, die Taint-Analyse ist ein Versuch),
    teilweise       gelaufen, einzelne Dateien nicht geprüft (deren offene Befunde fortgeschrieben),
    fortgeschrieben nicht gelaufen (fehlt, gescheitert, --ohne, Zeitbudget) — offene Befunde aus SonarQube übernommen,
    übersprungen    nichts zu prüfen (keine requirements*.txt, Pysa im Profil desktop)."""
    if s.vollstaendig:
        if s.status != "ok":
            return "übersprungen"
        return "Versuch" if kennung == "pysa" else "ok"
    return "teilweise" if s.status == "ok" else "fortgeschrieben"


def werkzeuge_angabe(je_werkzeug: dict[str, Schritt]) -> str:
    """Wert für sonar.analysis.werkzeuge: je Werkzeug „<name> <version> <status>“ (Version nur, wenn bekannt),
    getrennt mit „; “ — z. B. „bandit 1.9.4 ok; semgrep 1.179.0 ok; pip-audit übersprungen; pysa fortgeschrieben“.
    Ohne Komma und Gleichheitszeichen, damit der Scanner den Wert nie als Liste oder Zuweisung liest."""
    teile = []
    for kennung in WERKZEUGE:
        s = je_werkzeug.get(kennung)
        if s is None:
            continue
        version = re.sub(r"[^0-9A-Za-z.+-]", "", s.version or "")
        teile.append(" ".join(t for t in (kennung, version, werkzeug_status(kennung, s)) if t))
    return "; ".join(teile)


def restzeit(name: str, bis: float | None) -> int:
    """Zeitlimit eines Aufrufs: GRENZE des Werkzeugs, mit Frist (time.monotonic) höchstens bis dahin."""
    grenze = GRENZE[name]
    if bis is not None:
        grenze = min(grenze, int(bis - time.monotonic()))
    return max(grenze, 1)


def werkzeug(name: str, modul: str | None = None) -> list[str] | None:
    """Befehl für ein Werkzeug: neben dieser Python (venv), als Modul dieser Python, sonst im PATH."""
    exe = name + (".exe" if os.name == "nt" else "")
    ordner = Path(sys.executable).parent
    for kandidat in (ordner / exe, ordner / "Scripts" / exe, ordner / "bin" / name):
        if kandidat.is_file():
            return [str(kandidat)]
    if modul and importlib.util.find_spec(modul):
        return [sys.executable, "-m", modul]
    gefunden = shutil.which(name)
    return [gefunden] if gefunden else None


def _umgebung(**extra: str) -> dict:
    """Umgebung für Unterprozesse — ohne Scanner-Token: pip-audit lässt pip auflösen, und pip führt dabei Build-Code
    fremder Pakete aus. Den Token bekommt nur der Scanner (als extra)."""
    ohne_token = {k: v for k, v in os.environ.items() if k.upper() not in TOKEN_VARIABLEN}
    return {**ohne_token, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8", **extra}


def _baum_beenden(prozess: subprocess.Popen) -> None:
    """Prozess samt allen Kindern beenden. Ein einfaches kill() trifft nur den Startprozess: Semgrep lief nach
    Ablauf des Zeitlimits als semgrep-core mit 2 GB weiter (gemessen 06.10.2026), ebenso pyre und der Java-Teil
    des Scanners."""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(prozess.pid)], capture_output=True, timeout=60)
        else:
            os.killpg(prozess.pid, signal.SIGKILL)      # eigene Prozessgruppe (start_new_session)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        prozess.kill()
        prozess.wait(timeout=30)
    except (OSError, subprocess.SubprocessError):
        pass


def laufen_mit_grenze(befehl: list[str], cwd: Path, grenze: int, umgebung: dict, ausgabe=None) -> int | None:
    """Befehl mit Zeitlimit; Ausgabe in die Datei ausgabe (None = Bildschirm). Exit-Code, None bei Zeitüberschreitung.
    Bei Zeitüberschreitung oder Abbruch (Strg+C) wird der ganze Prozessbaum beendet."""
    prozess = subprocess.Popen(befehl, cwd=cwd, env=umgebung, stdin=subprocess.DEVNULL, stdout=ausgabe,
                               stderr=subprocess.STDOUT if ausgabe is not None else None,
                               start_new_session=os.name != "nt")
    try:
        return prozess.wait(timeout=grenze)
    except subprocess.TimeoutExpired:
        _baum_beenden(prozess)
        return None
    except BaseException:
        _baum_beenden(prozess)
        raise


def ausfuehren(befehl: list[str], cwd: Path, grenze: int, log: Path, umgebung: dict | None = None
               ) -> tuple[int | None, float]:
    """Befehl mit Zeitlimit; Ausgabe ins Protokoll. Rückgabe: (Exit-Code oder None bei Zeitüberschreitung, Sekunden)."""
    beginn = time.monotonic()
    with open(log, "w", encoding="utf-8", errors="replace") as datei:
        try:
            code = laufen_mit_grenze(befehl, cwd, grenze, umgebung or _umgebung(), datei)
        except OSError as fehler:
            datei.write(f"\n{fehler}\n")
            code = -1
    return code, time.monotonic() - beginn


def letzte_zeilen(log: Path, anzahl: int = 4) -> str:
    try:
        zeilen = [z.strip() for z in log.read_text(encoding="utf-8", errors="replace").splitlines() if z.strip()]
    except OSError:
        return ""
    return " | ".join(zeilen[-anzahl:])[:500]


def _abgebrochen(schritt: Schritt, code: int | None, log: Path, grenze: int) -> Schritt:
    schritt.status = "fehler"
    schritt.hinweis = (f"nach {dauer(grenze)} abgebrochen" if code is None
                       else f"Exit {code}: {letzte_zeilen(log)}")
    return schritt


def bandit_laufen(quelle: Path, ziel: Path, bis: float | None = None) -> Schritt:
    schritt = Schritt("Bandit")
    befehl = werkzeug("bandit", "bandit")
    if not befehl:
        schritt.hinweis = "nicht installiert"
        return schritt
    schritt.version = _version([*befehl, "--version"])
    roh, bericht, log = ziel / "bandit-roh.json", ziel / "bandit.json", ziel / "bandit.log"
    grenze = restzeit("bandit", bis)
    code, schritt.dauer = ausfuehren(
        [*befehl, "-r", ".", "-f", "json", "-o", str(roh), "-q",
         "--skip", ",".join(BANDIT_UEBERSPRINGEN), "-x", ",".join(bandit_ausschluesse(quelle))],
        quelle, grenze, log)
    if code not in (0, 1) or not roh.is_file():
        return _abgebrochen(schritt, code, log, grenze)
    try:
        daten = json.loads(roh.read_text(encoding="utf-8"))
    except ValueError as fehler:
        schritt.status, schritt.hinweis = "fehler", f"Bericht unlesbar ({fehler})"
        return schritt
    # Pfade relativ zur Projektwurzel mit '/', so findet SonarQube die Dateien (Bandit schreibt './x' bzw. '.\x').
    for treffer in daten.get("results") or []:
        treffer["filename"] = str(treffer.get("filename", "")).replace("\\", "/").removeprefix("./")
    bericht.write_text(json.dumps(daten, ensure_ascii=False), encoding="utf-8")
    roh.unlink(missing_ok=True)
    schritt.status, schritt.befunde, schritt.bericht = "ok", len(daten.get("results") or []), str(bericht)
    fehler = daten.get("errors") or []
    schritt.vollstaendig = not fehler
    if fehler:
        schritt.ungeprueft = sorted({str(f.get("filename", "")).replace("\\", "/").removeprefix("./")
                                     for f in fehler if f.get("filename")})
        schritt.hinweis = f"{len(fehler)} Dateien nicht lesbar"
    return schritt


def _semgrep_temp() -> Path | None:
    """Unter Windows ein Temp-Ordner ohne Leerzeichen und '~' für Semgrep.

    semgrep-core baut unter Windows seine RPC-Verbindung (socketpair) im Temp-Ordner; liegt der unter
    C:\\Users\\GERALD~1\\… oder C:\\Users\\Gerald Bischof\\…, scheitert das mit „Unix_error: Invalid argument
    socketpair“ (gemessen 06.10.2026, Semgrep 1.179.0). Unter %ProgramData%\\codepruefung\\tmp geht es.
    """
    if os.name != "nt":
        return None
    basis = Path(os.environ.get("ProgramData") or r"C:\ProgramData") / "codepruefung" / "tmp"
    if " " in str(basis) or "~" in str(basis):
        return None
    try:
        basis.mkdir(parents=True, exist_ok=True)
        return Path(tempfile.mkdtemp(prefix="sg", dir=basis))
    except OSError:
        return None


def semgrep_laufen(quelle: Path, ziel: Path, bis: float | None = None) -> Schritt:
    schritt = Schritt("Semgrep")
    befehl = werkzeug("semgrep")
    if not befehl:
        schritt.hinweis = ("nicht installiert" if os.name != "nt" else
                           "nicht installiert (läuft dann nur in der GitHub Action)")
        return schritt
    bericht, log = ziel / "semgrep.sarif", ziel / "semgrep.log"
    umgebung = _umgebung(SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")
    schritt.version = _version([*befehl, "--version"], umgebung)
    temp = _semgrep_temp()
    if temp:
        umgebung.update(TMP=str(temp), TEMP=str(temp))
    grenze = restzeit("semgrep", bis)
    try:
        # --exclude nimmt gitignore-Muster — die Sonar-Muster (**/x/**, docs/**, **/test_*.py) passen 1:1.
        code, schritt.dauer = ausfuehren(
            [*befehl, "scan", *(f"--config={r}" for r in SEMGREP_REGELSAETZE), "--metrics=off", "--sarif",
             f"--output={bericht}", "--disable-version-check", "--timeout=30",
             f"--max-target-bytes={SEMGREP_HOECHSTENS_BYTES}",
             *(f"--exclude={m}" for m in ausschluesse(quelle) + TEST_MUSTER),
             *(f"--exclude-rule={r}" for r in SEMGREP_UEBERSPRINGEN), "."],
            quelle, grenze, log, umgebung)
    finally:
        if temp:
            shutil.rmtree(temp, ignore_errors=True)
    if code not in (0, 1) or not bericht.is_file():
        protokoll = log.read_text(encoding="utf-8", errors="replace") if log.is_file() else ""
        if os.name == "nt" and ("semgrep-core" in protokoll or "socketpair" in protokoll):
            schritt.hinweis = "läuft auf diesem PC nicht (semgrep-core)"
            return schritt
        return _abgebrochen(schritt, code, log, grenze)
    try:
        daten = json.loads(bericht.read_text(encoding="utf-8"))
        schritt.befunde = umwandler.sarif_pfade_normalisieren(daten)
        bericht.write_text(json.dumps(daten, ensure_ascii=False), encoding="utf-8")
    except (ValueError, OSError) as fehler:
        schritt.status, schritt.hinweis = "fehler", f"Bericht unlesbar ({fehler})"
        return schritt
    schritt.status, schritt.bericht = "ok", str(bericht)
    # Zu große Dateien lässt Semgrep stillschweigend aus (Exit 0) — melden und als ungeprüft führen.
    zu_gross = zu_gross_fuer_semgrep(quelle)
    schritt.vollstaendig = not zu_gross
    hinweise = []
    if zu_gross:
        schritt.ungeprueft = zu_gross
        hinweise.append(f"{len(zu_gross)} Dateien über {SEMGREP_HOECHSTENS_BYTES // 1_000_000} MB nicht geprüft: "
                        + ", ".join(zu_gross[:3]) + (" …" if len(zu_gross) > 3 else ""))
    langsam = semgrep_zeitueberschreitungen(daten)
    if langsam:
        hinweise.append(f"{len(langsam)} Dateien wegen Zeitüberschreitung nur teilweise geprüft: "
                        + ", ".join(langsam[:3]) + (" …" if len(langsam) > 3 else ""))
    schritt.hinweis = "; ".join(hinweise)
    return schritt


def semgrep_zeitueberschreitungen(daten: dict) -> list[str]:
    """Dateien, bei denen Semgrep Regeln wegen --timeout abbrach (nach 3 solchen lässt es die übrigen Regeln für
    die Datei aus). Steht nur als Text in invocations/toolExecutionNotifications („Timeout when running <regel> on
    <datei>:“)."""
    dateien = set()
    for lauf in daten.get("runs") or []:
        for aufruf in lauf.get("invocations") or []:
            for meldung in aufruf.get("toolExecutionNotifications") or []:
                if ((meldung.get("descriptor") or {}).get("id") or "").lower() != "timeout":
                    continue
                treffer = re.search(r" on (.+?):\s*$", (meldung.get("message") or {}).get("text") or "")
                if treffer:
                    dateien.add(treffer.group(1).replace("\\", "/").removeprefix("./"))
    return sorted(dateien)


def _osv_schwere(luecken: dict[str, list[str]], bis: float | None = None) -> dict[str, tuple[str | None, float | None]]:
    """Schwere je Schwachstelle von api.osv.dev (eigene ID, sonst GHSA-Alias) — fehlt sie, bleibt sie leer.
    Höchstens OSV_HOECHSTENS Abfragen und OSV_GESAMT Sekunden (bzw. bis zur Frist)."""
    raus: dict[str, tuple[str | None, float | None]] = {}
    ende = time.monotonic() + OSV_GESAMT
    ende = min(ende, bis) if bis is not None else ende
    abfragen = 0
    for kennung, aliase in luecken.items():
        for k in [kennung] + [a for a in aliase if a.startswith("GHSA-") and a != kennung]:
            rest = ende - time.monotonic()
            if abfragen >= OSV_HOECHSTENS or rest < 1:
                return raus
            abfragen += 1
            try:
                with urllib.request.urlopen(OSV_URL + urllib.parse.quote(k), timeout=min(10.0, rest)) as antwort:
                    text, wert = umwandler.schwere_aus_osv(json.load(antwort))
            except (urllib.error.URLError, TimeoutError, ValueError, OSError):
                continue
            if text or wert is not None:
                raus[kennung] = (text, wert)
                break
    return raus


def ohne_windows_pakete(datei: Path, linux: bool | None = None) -> Path | None:
    """Unter Linux: Kopie der requirements-Datei neben dem Original, in der reine Windows-Pakete (WINDOWS_PAKETE)
    ohne eigene Markierung ein '; sys_platform == "win32"' bekommen — pip überspringt sie dann, statt an der ganzen
    Datei zu scheitern. Zeilen bleiben, wo sie sind; verschachtelte -r/-c lösen sich wie beim Original auf.
    None = nichts zu ändern (oder Windows). Der Aufrufer löscht die Kopie."""
    if not (platform.system() == "Linux" if linux is None else linux):
        return None
    zeilen, geaendert = [], False
    for zeile in datei.read_text(encoding="utf-8", errors="replace").splitlines():
        rein = zeile.split(" #", 1)[0].strip()
        treffer = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", rein)
        if treffer and ";" not in rein and umwandler.paketname(treffer.group(1)) in WINDOWS_PAKETE:
            zeile, geaendert = rein + ' ; sys_platform == "win32"', True
        zeilen.append(zeile)
    if not geaendert:
        return None
    kopie = datei.with_name(f".pruefpipeline-linux-{datei.name}")
    kopie.write_text("\n".join(zeilen) + "\n", encoding="utf-8")
    return kopie


def _nur_gepinnt(datei: Path, ziel: Path) -> Path | None:
    """Ersatz-requirements nur mit exakt gepinnten Paketen (name==version) — für pip-audit --no-deps."""
    zeilen = []
    for zeile in datei.read_text(encoding="utf-8", errors="replace").splitlines():
        rein = zeile.split(" #", 1)[0].strip()
        if re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[^\]]*\])?\s*==\s*[0-9][^\s;,*]*\s*(;.*)?$", rein):
            zeilen.append(rein)
    if not zeilen:
        return None
    ziel.write_text("\n".join(zeilen) + "\n", encoding="utf-8")
    return ziel


def pip_audit_laufen(quelle: Path, ziel: Path, bis: float | None = None) -> Schritt:
    schritt = Schritt("pip-audit")
    dateien = dateien_finden(quelle, "requirements*.txt")
    if not dateien:
        schritt.hinweis, schritt.vollstaendig = "keine requirements*.txt", True
        return schritt
    befehl = werkzeug("pip-audit", "pip_audit")
    if not befehl:
        schritt.hinweis = "nicht installiert"
        return schritt
    beginn = time.monotonic()
    schritt.version = _version([*befehl, "--version"])
    berichte, probleme, ungeprueft = [], [], []
    for nr, datei in enumerate(dateien, 1):
        rel = datei.relative_to(quelle).as_posix()
        if bis is not None and bis - time.monotonic() < WERKZEUG_MINDESTENS:
            probleme.append(f"{rel}: Zeitbudget aufgebraucht")
            ungeprueft.append(rel)
            continue
        roh, log = ziel / f"pip-audit-{nr}.json", ziel / f"pip-audit-{nr}.log"
        grundbefehl = [*befehl, "-f", "json", "-o", str(roh), "--progress-spinner", "off", "--desc", "on",
                       "--aliases", "on"]
        linux_kopie = ohne_windows_pakete(datei)
        try:
            code, _ = ausfuehren([*grundbefehl, "-r", str(linux_kopie or datei)], quelle,
                                 restzeit("pip-audit", bis), log)
        finally:
            if linux_kopie:
                linux_kopie.unlink(missing_ok=True)
        if code not in (0, 1) or not roh.is_file():
            # Auflösen gescheitert: nur die exakt gepinnten Pakete prüfen — die Datei gilt dann als nicht ganz geprüft.
            ungeprueft.append(rel)
            ersatz = _nur_gepinnt(datei, ziel / f"pip-audit-{nr}-gepinnt.txt")
            if ersatz:
                code, _ = ausfuehren([*grundbefehl, "-r", str(ersatz), "--no-deps", "--disable-pip"],
                                     quelle, restzeit("pip-audit", bis), log)
            if code not in (0, 1) or not roh.is_file():
                probleme.append(f"{rel}: {letzte_zeilen(log, 2) or 'nicht auflösbar'}")
                continue
            probleme.append(f"{rel}: nur gepinnte Pakete geprüft (Auflösen ging nicht)")
        try:
            bericht = json.loads(roh.read_text(encoding="utf-8"))
        except ValueError:
            probleme.append(f"{rel}: Bericht unlesbar")
            if rel not in ungeprueft:
                ungeprueft.append(rel)
            continue
        zeilen = umwandler.anforderungs_zeilen(datei.read_text(encoding="utf-8", errors="replace"))
        berichte.append((rel, bericht, zeilen))
    luecken = {v["id"]: v.get("aliases") or [] for _, b, _ in berichte
               for p in b.get("dependencies") or [] for v in p.get("vulns") or [] if v.get("id")}
    schwere = _osv_schwere(luecken, bis) if luecken else {}
    sarif = umwandler.pip_audit_sarif(berichte, schwere, schritt.version)
    schritt.dauer = time.monotonic() - beginn
    schritt.befunde = sum(len(lauf["results"]) for lauf in sarif["runs"])
    schritt.hinweis = "; ".join(probleme)
    schritt.ungeprueft = ungeprueft
    schritt.vollstaendig = not ungeprueft
    if not berichte:
        schritt.status = "fehler"
        return schritt
    schritt.status = "ok"
    if schritt.befunde:
        pfad = ziel / "pip-audit.sarif"
        pfad.write_text(json.dumps(sarif, ensure_ascii=False, indent=1), encoding="utf-8")
        schritt.bericht = str(pfad)
    return schritt


def _version(befehl: list[str], umgebung: dict | None = None) -> str | None:
    """Versionsnummer aus der Ausgabe von '<werkzeug> --version' („bandit 1.9.4 …“, „1.179.0“); bei pyre die
    „Client version“ (davor steht die Binary version, ein Hash oder eine eigene Nummer)."""
    try:
        lauf = subprocess.run(befehl, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=60, env=umgebung or _umgebung(), stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = lauf.stdout or ""
    # (?<!\d): die Nummer beginnt nur am Anfang einer Ziffernfolge — gleicher Treffer, aber linear statt quadratisch
    # bei langen Ziffernfolgen ohne Punkt (python:S8786).
    treffer = re.search(r"Client version:\s*(\d+(?:\.\d+)+)", text) or re.search(r"(?<!\d)(\d+(?:\.\d+)+)", text)
    return treffer.group(1) if treffer else None


def _paket_version(python: Path, paket: str) -> str | None:
    """Version eines installierten Pakets in der venv dieser Python (Pysa: eigene venv in der Action)."""
    if not python.is_file():
        return None
    return _version([str(python), "-c", f"import importlib.metadata as m; print(m.version({paket!r}))"])


def pysa_programm() -> Path | None:
    """pyre aus der eigenen Pysa-venv der Action ($RUNNER_TEMP/pysa-venv), aus PYSA_PYRE oder dem PATH."""
    kandidaten = []
    if os.environ.get("PYSA_PYRE"):
        kandidaten.append(Path(os.environ["PYSA_PYRE"]))
    if os.environ.get("RUNNER_TEMP"):
        kandidaten.append(Path(os.environ["RUNNER_TEMP"]) / "pysa-venv" / "bin" / "pyre")
    kandidaten.append(Path(sys.executable).parent / "pyre")
    for kandidat in kandidaten:
        if kandidat.is_file():
            return kandidat
    gefunden = shutil.which("pyre")
    return Path(gefunden) if gefunden else None


def pysa_laufen(quelle: Path, ziel: Path, profil: str, bis: float | None = None) -> Schritt:
    """Taint-Analyse mit Pysa — Versuch: jeder Fehler wird zum Hinweis, der Lauf geht weiter."""
    schritt = Schritt("Pysa (Versuch)")
    if profil != "web":
        # Im Profil desktop gehört Pysa nicht dazu — alte Pysa-Befunde (Profil vorher web) dürfen sich schließen.
        schritt.hinweis, schritt.vollstaendig = "nur im Profil web", True
        return schritt
    if platform.system() != "Linux":
        schritt.hinweis = "läuft nur unter Linux (in der GitHub Action)"
        return schritt
    pyre = pysa_programm()
    if not pyre:
        schritt.hinweis = "pyre-check nicht installiert"
        return schritt
    schritt.version = _paket_version(pyre.resolve().parent / "python", "pyre-check")
    daten = pyre.resolve().parent.parent / "lib" / "pyre_check"
    if not daten.is_dir():
        schritt.hinweis = f"Daten von pyre-check fehlen ({daten})"
        return schritt
    konfig, pyrefly_konfig = quelle / ".pyre_configuration", quelle / "pyrefly.toml"
    if konfig.exists() or (quelle / ".pyre").exists() or pyrefly_konfig.exists():
        schritt.hinweis = "Projekt hat eigene Pyre/Pyrefly-Konfiguration — Pysa ausgelassen"
        return schritt
    modelle = [str(daten / "taint"), str(daten / "third_party_taint")]
    if PYSA_MODELLE.is_dir():
        modelle.append(str(PYSA_MODELLE))
    konfig.write_text(json.dumps({
        "source_directories": ["."], "taint_models_path": modelle, "typeshed": str(daten / "typeshed"),
        "site_package_search_strategy": "pep561", "exclude": pyre_ausschluesse(quelle), "strict": False,
    }, indent=2), encoding="utf-8")
    # Typprüfung macht pyrefly (seit pyre-check 0.10 Standard): dieselben Ausschlüsse wie Sonar, Testcode raus.
    pyrefly_konfig.write_text(
        "# Vorübergehend angelegt von der Prüfpipeline (Pysa) — wird nach dem Lauf wieder gelöscht.\n"
        'project-includes = ["**/*.py"]\n'
        "project-excludes = [" + ", ".join(json.dumps(m) for m in ausschluesse(quelle) + TEST_MUSTER) + "]\n",
        encoding="utf-8")
    venv = pyre.resolve().parent
    umgebung = _umgebung(PATH=f"{venv}{os.pathsep}{os.environ.get('PATH', '')}", VIRTUAL_ENV=str(venv.parent))
    if (venv / "pyrefly").is_file():
        umgebung["PYREFLY_BINARY"] = str(venv / "pyrefly")
    ausgabe, log = ziel / "pysa", ziel / "pysa.log"
    grenze = restzeit("pysa", bis)
    try:
        # Nur die klassischen Sicherheitsregeln (Einschleusung, SSRF, XSS, Dateisystem …): die übrigen von pyre-check
        # (z. B. 5051–5053 „String könnte SQL/HTML/URL sein“, 6302 Exception an den Nutzer) brachten beim ersten
        # Lauf auf verwaltung 99 von 124 Befunden, fast alle ohne echten Fehler.
        code, schritt.dauer = ausfuehren(
            [str(pyre), "--dot-pyre-directory", str(ziel / "pyre-arbeit"), "analyze", "--no-verify",
             *(f"--rule={r}" for r in sorted(umwandler.PYSA_REGELN)), "--save-results-to", str(ausgabe)],
            quelle, grenze, log, umgebung)
    finally:
        konfig.unlink(missing_ok=True)
        pyrefly_konfig.unlink(missing_ok=True)
        shutil.rmtree(quelle / ".pyre", ignore_errors=True)
    if code != 0:
        if in_actions() and log.is_file():                # Versuch: Protokoll aufklappbar im Lauf zeigen
            zeilen = log.read_text(encoding="utf-8", errors="replace").splitlines()
            print("::group::Pysa-Protokoll (letzte 60 Zeilen)\n" + "\n".join(zeilen[-60:]) + "\n::endgroup::",
                  flush=True)
        return _abgebrochen(schritt, code, log, grenze)
    dateien = sorted(ausgabe.glob("taint-output*.json"))
    if not dateien:
        schritt.status, schritt.hinweis = "fehler", "keine taint-output*.json"
        return schritt
    befunde = []
    for datei in dateien:
        with open(datei, encoding="utf-8", errors="replace") as f:
            befunde += umwandler.pysa_eintraege(f)
    schritt.version = schritt.version or _version([str(pyre), "--version"])
    sarif = umwandler.pysa_sarif(befunde, schritt.version, str(quelle.resolve().as_posix()))
    # Befunde in fremdem Code (site-packages) haben keinen Ort im Projekt — SonarQube hängte sie ans Projekt.
    lauf = sarif["runs"][0]
    lauf["results"] = [e for e in lauf["results"] if (quelle / e["locations"][0]["physicalLocation"]
                                                       ["artifactLocation"]["uri"]).is_file()]
    pfad = ziel / "pysa.sarif"
    pfad.write_text(json.dumps(sarif, ensure_ascii=False, indent=1), encoding="utf-8")
    schritt.status, schritt.befunde, schritt.bericht = "ok", len(lauf["results"]), str(pfad)
    schritt.vollstaendig = True
    if len(lauf["results"]) < len(befunde):
        schritt.hinweis = f"{len(befunde) - len(lauf['results'])} Befunde außerhalb des Projekts weggelassen"
    return schritt


# ---------------------------------------------------------------------------------------------------------------
# SonarQube
# ---------------------------------------------------------------------------------------------------------------

def token_holen() -> str:
    """Scanner-Token: SONAR_TOKEN oder SONAR_SCAN_TOKEN, sonst (nur am PC) per ssh vom Server. Nie ausgeben."""
    for name in ("SONAR_TOKEN", "SONAR_SCAN_TOKEN"):
        token = os.environ.get(name, "").strip()
        if token:
            return token
    if in_actions():
        raise RuntimeError("Secret SONAR_TOKEN fehlt im Repo (ausrollen.py setzt es).")
    try:
        lauf = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", SERVER, "cat", TOKEN_DATEI],
                              capture_output=True, text=True, encoding="utf-8", timeout=60)
    except (OSError, subprocess.TimeoutExpired) as fehler:
        raise RuntimeError(f"Scanner-Token nicht erhältlich: ssh {SERVER} ging nicht ({fehler}).") from None
    token = lauf.stdout.strip()
    if lauf.returncode != 0 or not token:
        grund = lauf.stderr.strip().splitlines()[-1] if lauf.stderr.strip() else f"Exit {lauf.returncode}"
        raise RuntimeError(f"Scanner-Token nicht erhältlich ({grund}). Alternativ SONAR_SCAN_TOKEN setzen.")
    return token


def sonar(host: str, pfad: str, token: str, **parameter) -> dict:
    url = host.rstrip("/") + pfad + ("?" + urllib.parse.urlencode(parameter) if parameter else "")
    anfrage = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(anfrage, timeout=30) as antwort:
        return json.load(antwort)


def wecken(token: str) -> bool:
    """SonarQube wecken bzw. wach halten. Nie fatal: schläft es nicht oder fehlt die Verwaltung, wartet token_pruefen
    ohnehin, bis SonarQube UP meldet. True = es schlief und startet jetzt."""
    if not WECKEN_URL:
        return False
    anfrage = urllib.request.Request(WECKEN_URL, data=b"", method="POST", headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(anfrage, timeout=20) as antwort:
            zustand = json.load(antwort).get("zustand")
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as fehler:
        print(f"  (Weckruf an die Verwaltung ging nicht: {fehler} — weiter ohne)", flush=True)
        return False
    if zustand == "geweckt":
        print("- SonarQube schlief (Bedarfsbetrieb) und wird geweckt — das dauert 1–3 Minuten.", flush=True)
        return True
    return False


def token_pruefen(host: str, token: str) -> None:
    try:
        gueltig = sonar(host, "/api/authentication/validate", token).get("valid")
    except (urllib.error.URLError, TimeoutError, ValueError) as fehler:
        # 502 o. ä. beim Start: SonarQube startet gerade neu (OOM am 4-GB-VPS oder Einspielen) — einmal abwarten
        if not sonar_bereit(host, None):
            raise RuntimeError(f"SonarQube ({host}) nicht erreichbar: {fehler}") from None
        try:
            gueltig = sonar(host, "/api/authentication/validate", token).get("valid")
        except (urllib.error.URLError, TimeoutError, ValueError) as fehler2:
            raise RuntimeError(f"SonarQube ({host}) nicht erreichbar: {fehler2}") from None
    if not gueltig:
        raise RuntimeError("Der Scanner-Token wird von SonarQube nicht angenommen (widerrufen?).")


def bericht_lesen(pfad: Path) -> dict:
    """report-task.txt des Scanners (ceTaskId, dashboardUrl …)."""
    werte = {}
    if pfad.is_file():
        for zeile in pfad.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in zeile:
                k, v = zeile.split("=", 1)
                werte[k.strip()] = v.strip()
    return werte


def server_warten(host: str, token: str, aufgabe: str, bis: float | None = None) -> tuple[str, str | None]:
    """Warten, bis SonarQube die Analyse verarbeitet hat (höchstens GRENZE['server'] bzw. bis zur Frist).
    Rückgabe: (Status, Fehlermeldung)."""
    grenze = restzeit("server", bis)
    beginn, pause, stoerungen, letzter = time.monotonic(), 2.0, 0, ""
    while True:
        try:
            antwort = sonar(host, "/api/ce/task", token, id=aufgabe)["task"]
            stoerungen = 0
            if antwort["status"] in ("SUCCESS", "FAILED", "CANCELED"):
                return antwort["status"], antwort.get("errorMessage")
        except urllib.error.HTTPError as fehler:
            stoerungen += 1             # 401/403/5xx auch während eines Neustarts von SonarQube
            letzter = f"HTTP {fehler.code}"
        except (urllib.error.URLError, TimeoutError, KeyError, ValueError):
            stoerungen += 1
            letzter = "keine Antwort"
        if stoerungen >= 30:               # ~4 Minuten am Stück — länger als ein Neustart
            if letzter in ("HTTP 401", "HTTP 403"):
                return "UNBEKANNT", f"keine Leserechte auf api/ce/task ({letzter})"
            return "UNBEKANNT", f"SonarQube antwortet nicht mehr auf api/ce/task ({letzter})"
        if time.monotonic() - beginn > grenze:
            return "ZEITÜBERSCHREITUNG", f"nach {dauer(grenze)} noch nicht verarbeitet"
        time.sleep(pause)
        pause = min(pause * 1.5, 10.0)


# SonarQube startet am 4-GB-VPS gelegentlich neu (Elasticsearch per OOM beendet). Eine Analyse, die gerade
# verarbeitet wurde, scheitert dann mit solchen Meldungen, und während des Hochfahrens antwortet api/ce/task mit
# 401/502. Dann einmal warten, bis SonarQube wieder UP ist, und neu hochladen — statt den Lauf rot zu machen.
VORUEBERGEHEND = ("Fail to execute es request", "Unable to load component class", "ElasticSearch", "Elasticsearch",
                  "NoNodeAvailable", "antwortet nicht mehr", "Leserechte auf api/ce/task", "UNAVAILABLE")


def voruebergehend(status: str, meldung: str | None) -> bool:
    """Scheitern, das nach einem Neustart von SonarQube aussieht (nicht: echter Analysefehler, Zeitüberschreitung)."""
    if status == "ZEITÜBERSCHREITUNG":
        return False
    return status == "UNBEKANNT" or any(t in (meldung or "") for t in VORUEBERGEHEND)


def sonar_bereit(host: str, bis: float | None, grenze: int = 600) -> bool:
    """Warten, bis SonarQube wieder UP meldet (höchstens grenze Sekunden bzw. bis zur Frist minus 5 Minuten)."""
    ende = time.monotonic() + grenze
    if bis is not None:
        ende = min(ende, bis - 300)
    while time.monotonic() < ende:
        try:
            anfrage = urllib.request.Request(host.rstrip("/") + "/api/system/status")
            with urllib.request.urlopen(anfrage, timeout=15) as antwort:
                if json.load(antwort).get("status") == "UP":
                    time.sleep(20)          # Web und Rechenteil kommen kurz nach „UP“ ganz hoch
                    return True
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            pass
        time.sleep(15)
    return False


# ---------------------------------------------------------------------------------------------------------------
# Fortschreiben: Befunde eines Werkzeugs, das diesmal nicht (ganz) lief, bleiben offen
# ---------------------------------------------------------------------------------------------------------------
# SonarQube schließt jeden externen Befund, der im neuen Bericht fehlt, als behoben — auch wenn das Werkzeug nur
# nicht lief (Pysa am PC, Semgrep-Fehler, pip-audit kam nicht durch). Die Verwaltung hielte die Pakete dann für
# erledigt, erteilte womöglich die Freigabe, und beim nächsten vollständigen Lauf kämen dieselben Befunde in neuen
# Paketen wieder. Darum: die offenen Befunde solcher Werkzeuge aus SonarQube holen und unverändert (Regel samt
# Name/Beschreibung/Stufe, Datei, Meldung, Zeile — per Zeilen-Hash dem heutigen Code nachgeführt) wieder mitgeben.
# SonarQube erkennt sie als dieselben Befunde (gleicher Schlüssel, Schwere, Impact, Markierung; live geprüft
# 06.10.2026: vollständig → fortgeschrieben mit verschobenem Code → vollständig, alle 23 Schlüssel gleich).
# Sie gelten erst als behoben, wenn das Werkzeug wieder läuft und sie nicht mehr findet.

STATUS_FORTSCHREIBEN = "OPEN,CONFIRMED,FALSE_POSITIVE,ACCEPTED"
STUFE_AUS_SCHWERE = {"BLOCKER": "error", "CRITICAL": "error", "MAJOR": "warning", "MINOR": "note", "INFO": "note"}
# (issue_severity, issue_confidence), die SonarQubes Bandit-Import wieder auf dieselbe Schwere abbildet
BANDIT_AUS_SCHWERE = {"BLOCKER": ("HIGH", "HIGH"), "CRITICAL": ("HIGH", "MEDIUM"), "MAJOR": ("MEDIUM", "MEDIUM"),
                      "MINOR": ("LOW", "LOW"), "INFO": ("LOW", "LOW")}


def werkzeug_der_regel(regel: str) -> tuple[str, str, str] | None:
    """'external_Semgrep OSS:python.x' → ('semgrep', 'Semgrep OSS', 'python.x'); None bei Sonars eigenen Regeln und
    fremden Werkzeugen."""
    if not regel.startswith("external_") or ":" not in regel:
        return None
    engine, kennung = regel[len("external_"):].split(":", 1)
    werkzeug_name = next((w for w in WERKZEUGE if engine.lower().startswith(w)), None)
    return (werkzeug_name, engine, kennung) if werkzeug_name else None


def externe_befunde_holen(host: str, token: str, schluessel: str) -> list[dict]:
    """Offene (auch als Fehlalarm/akzeptiert markierte) Befunde der Zusatzwerkzeuge eines Projekts aus SonarQube.
    Externe Befunde haben immer den Typ VULNERABILITY (SARIF-Import und alle Bandit-Regeln) — das hält die Liste
    klein (verwaltung: 39 statt 795). Nicht nach Impact filtern: Bandit B113 kommt mit MAINTAINABILITY an (gemessen
    06.10.2026). Kennt SonarQube das Projekt noch nicht (erster Scan), ist die Liste leer."""
    raus, seite = [], 1
    while True:
        try:
            j = sonar(host, "/api/issues/search", token, components=schluessel, issueStatuses=STATUS_FORTSCHREIBEN,
                      types="VULNERABILITY", ps=500, p=seite)
        except urllib.error.HTTPError as fehler:
            if fehler.code == 404 and seite == 1:
                return []
            raise
        raus += [i for i in j.get("issues") or [] if werkzeug_der_regel(i.get("rule") or "")]
        gesamt = int((j.get("paging") or {}).get("total") or j.get("total") or 0)
        if not j.get("issues") or seite * 500 >= min(gesamt, 10_000):
            return raus
        seite += 1


def zeilen_hashes(datei: Path) -> list[str]:
    """SonarQubes Zeilen-Hash je Zeile (Index 0 = Zeile 1): md5 der Zeile ohne Leerzeichen und Tabs, leere Zeile ''
    (wie SourceLineHashesComputer; geprüft 06.10.2026 am Feld „hash“ von api/issues/search)."""
    try:
        text = datei.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    raus = []
    for zeile in re.split(r"\r\n|\r|\n", text):
        rest = zeile.replace(" ", "").replace("\t", "")
        raus.append(hashlib.md5(rest.encode("utf-8")).hexdigest() if rest else "")
    return raus


def zeile_nachfuehren(hashes: list[str], alt: int | None, soll: str | None) -> int | None:
    """Wo steht die Zeile eines Befunds jetzt? SonarQube kennt Zeile und Hash aus der letzten Analyse; hat sich der
    Code inzwischen verschoben, liegt der Befund in der nächstgelegenen Zeile mit demselben Hash. Ohne Treffer bleibt
    die alte Zeile. (Mit der alten Zeile allein erkannte SonarQube den Befund beim nächsten vollständigen Lauf nicht
    wieder — neuer Schlüssel, alter geschlossen.)"""
    if not soll or alt is None:
        return alt
    if 1 <= alt <= len(hashes) and hashes[alt - 1] == soll:
        return alt
    treffer = [n for n, h in enumerate(hashes, 1) if h == soll]
    return min(treffer, key=lambda n: (abs(n - alt), n)) if treffer else alt


def gemeldet(bericht: str | None) -> set[tuple[str, str]]:
    """(Datei, Regel-ID) aller Befunde in einem Bericht dieses Laufs (Bandit-JSON oder SARIF)."""
    if not bericht:
        return set()
    try:
        daten = json.loads(Path(bericht).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    if "runs" not in daten:
        return {(str(r.get("filename", "")), str(r.get("test_id", ""))) for r in daten.get("results") or []}
    raus = set()
    for lauf in daten.get("runs") or []:
        for e in lauf.get("results") or []:
            for ort in e.get("locations") or []:
                uri = ((ort.get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri") or ""
                raus.add((str(uri), str(e.get("ruleId", ""))))
    return raus


def regel_angaben(host: str, token: str, regel: str) -> dict | None:
    """Name, Beschreibung und Stufe einer SARIF-Regel, wie SonarQube sie führt (api/rules/show) — None, wenn nicht
    abrufbar. Damit lässt sich die Regel im Fortschreib-Bericht unverändert wieder angeben: Name = shortDescription,
    Beschreibung = fullDescription (beides wortgleich gespeichert, geprüft 06.10.2026), Stufe aus der Schwere."""
    try:
        r = sonar(host, "/api/rules/show", token, key=regel).get("rule") or {}
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None
    if not r.get("name"):
        return None
    beschreibung = {s.get("key"): s.get("content") for s in r.get("descriptionSections") or []}.get("default")
    return {"name": r["name"], "beschreibung": beschreibung or "",
            "stufe": STUFE_AUS_SCHWERE.get(str(r.get("severity") or "").upper(), "warning")}


def _sarif_regel(kennung: str, angaben: dict) -> dict:
    regel = {"id": kennung, "shortDescription": {"text": angaben["name"]},
             "defaultConfiguration": {"level": angaben["stufe"]}}
    if angaben.get("beschreibung"):
        regel["fullDescription"] = {"text": angaben["beschreibung"]}
    return regel


def fortschreib_berichte(issues: list[dict], luecken: dict[str, Schritt], quelle: Path,
                         regeln=None) -> tuple[dict | None, dict | None, dict[str, int]]:
    """Aus offenen Sonar-Befunden die Berichte zum Fortschreiben: (Bandit-JSON, SARIF, Anzahl je Werkzeug).

    luecken: Werkzeug → sein Schritt, wo das Ergebnis nicht vollständig ist. Fortgeschrieben wird, was zu einem
    dieser Werkzeuge gehört, in einer seiner ungeprüften Dateien liegt (keine Liste = alle Dateien), die Datei noch
    gibt, nicht ausgeschlossen ist (ausschluesse(quelle)) und was das Werkzeug in diesem Lauf nicht ohnehin gemeldet
    hat. Befunde ohne Datei bleiben weg. Die Zeile
    wird über SonarQubes Zeilen-Hash auf den heutigen Code nachgeführt (zeile_nachfuehren).
    regeln: Regelschlüssel → regel_angaben (dict, oder eine Funktion, die sie liefert — gefragt wird nur nach Regeln,
    die wirklich fortgeschrieben werden). Nur damit stehen die Regeln im SARIF — SonarQube leitet daraus den Impact
    (SECURITY mit Schwere) ab; ohne Angabe fiel er auf MAINTAINABILITY/MEDIUM zurück. Eine Regel ohne Angaben
    bleibt draußen: halbe Angaben würden Name und Beschreibung der Regel in SonarQube überschreiben."""
    if regeln is None:
        regeln = {}
    holen = regeln.get if isinstance(regeln, dict) else regeln
    schon = {w: gemeldet(s.bericht) for w, s in luecken.items()}
    raus = ausschluesse(quelle)
    bandit: list[dict] = []
    laeufe: dict[str, list[dict]] = {}
    anzahl: dict[str, int] = {}
    hashes: dict[str, list[str]] = {}
    for i in issues:
        teile = werkzeug_der_regel(i.get("rule") or "")
        if not teile or teile[0] not in luecken:
            continue
        werkzeug_name, engine, kennung = teile
        s = luecken[werkzeug_name]
        komponente = i.get("component") or ""
        pfad = komponente.split(":", 1)[1] if ":" in komponente else ""
        if (not pfad or (s.ungeprueft and pfad not in s.ungeprueft) or not (quelle / pfad).is_file()
                or ausgeschlossen(pfad, raus)):
            continue
        if (pfad, kennung) in schon[werkzeug_name]:
            continue
        zeile = i.get("line") or (i.get("textRange") or {}).get("startLine")
        if zeile and i.get("hash"):
            if pfad not in hashes:
                hashes[pfad] = zeilen_hashes(quelle / pfad)
            zeile = zeile_nachfuehren(hashes[pfad], int(zeile), i["hash"])
        schwere = str(i.get("severity") or "MAJOR").upper()
        meldung = str(i.get("message") or kennung)
        anzahl[werkzeug_name] = anzahl.get(werkzeug_name, 0) + 1
        if werkzeug_name == "bandit":
            sev, conf = BANDIT_AUS_SCHWERE.get(schwere, ("MEDIUM", "MEDIUM"))
            bandit.append({"filename": pfad, "test_id": kennung, "test_name": kennung, "issue_text": meldung,
                           "line_number": int(zeile or 1), "line_range": [int(zeile or 1)], "col_offset": 0,
                           "issue_severity": sev, "issue_confidence": conf})
            continue
        ort: dict = {"physicalLocation": {"artifactLocation": {"uri": pfad}}}
        if zeile:
            ort["physicalLocation"]["region"] = {"startLine": int(zeile)}
        laeufe.setdefault(engine, []).append({"ruleId": kennung, "level": STUFE_AUS_SCHWERE.get(schwere, "warning"),
                                              "message": {"text": meldung}, "locations": [ort]})
    bandit_bericht = {"errors": [], "metrics": {}, "results": bandit} if bandit else None
    runs = []
    for engine, ergebnisse in laeufe.items():
        kennungen = sorted({e["ruleId"] for e in ergebnisse})
        treiber_regeln = [_sarif_regel(k, angaben) for k in kennungen
                          for angaben in [holen(f"external_{engine}:{k}")] if angaben]
        runs.append({"tool": {"driver": {"name": engine, "rules": treiber_regeln}}, "results": ergebnisse})
    sarif = {"$schema": umwandler.SARIF_SCHEMA, "version": "2.1.0", "runs": runs} if runs else None
    return bandit_bericht, sarif, anzahl


def fortschreiben(je_werkzeug: dict[str, Schritt], quelle: Path, ziel: Path, host: str, token: str,
                  schluessel: str) -> tuple[list[str], list[str]]:
    """Offene Befunde unvollständig gelaufener Werkzeuge aus SonarQube fortschreiben → (Bandit-, SARIF-Berichte).
    RuntimeError, wenn SonarQube sie nicht liefert — dann darf nichts hochgeladen werden."""
    luecken = {w: s for w, s in je_werkzeug.items() if not s.vollstaendig}
    if not luecken:
        return [], []
    try:
        issues = externe_befunde_holen(host, token, schluessel)
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError, OSError) as fehler:
        raise RuntimeError(f"offene Befunde von {', '.join(sorted(luecken))} nicht abrufbar ({fehler}) — die "
                           "Analyse würde sie als behoben schließen, darum nicht hochgeladen") from None
    # Regel-Angaben nur für fortgeschriebene SARIF-Regeln (Bandit-Regeln bringt SonarQubes Bandit-Import selbst mit)
    bandit, sarif, anzahl = fortschreib_berichte(issues, luecken, quelle,
                                                 lambda regel: regel_angaben(host, token, regel))
    berichte_bandit, berichte_sarif = [], []
    if bandit:
        pfad = ziel / "bandit-fortgeschrieben.json"
        pfad.write_text(json.dumps(bandit, ensure_ascii=False), encoding="utf-8")
        berichte_bandit.append(str(pfad))
    if sarif:
        pfad = ziel / "fortgeschrieben.sarif"
        pfad.write_text(json.dumps(sarif, ensure_ascii=False, indent=1), encoding="utf-8")
        berichte_sarif.append(str(pfad))
    for w, n in anzahl.items():
        s = luecken[w]
        text = f"{n} offene Befunde aus SonarQube fortgeschrieben (bleiben, bis {s.name} wieder vollständig läuft)"
        s.hinweis = f"{s.hinweis}; {text}" if s.hinweis else text
    return berichte_bandit, berichte_sarif


def java_argumente() -> list[str]:
    """In GitHub Actions das vorinstallierte Java nehmen — spart den JRE-Download vom Server (4 GB RAM)."""
    for name in ("JAVA_HOME_21_X64", "JAVA_HOME_17_X64"):
        java = Path(os.environ.get(name, "")) / "bin" / "java"
        if os.environ.get(name) and java.is_file():
            return ["--sonar-scanner-java-exe-path", str(java), "--skip-jre-provisioning"]
    return []


# ---------------------------------------------------------------------------------------------------------------
# Ablauf
# ---------------------------------------------------------------------------------------------------------------

def zusammenfassung(schritte: list[Schritt], kopf: str) -> str:
    zeilen = [f"### {kopf}", "", "| Schritt | Ergebnis | Dauer | Befunde | Hinweis |", "|---|---|---|---|---|"]
    for s in schritte:
        zeilen.append(f"| {s.name} | {s.status} | {dauer(s.dauer)} | {'' if s.befunde is None else s.befunde} | "
                      f"{s.hinweis.replace('|', '/')} |")
    return "\n".join(zeilen) + "\n"


def argumente_lesen(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Prüfpipeline: Bandit, Semgrep, pip-audit, Pysa → SonarQube-Scanner.")
    p.add_argument("--quelle", default=".", help="Projektwurzel (Standard: aktueller Ordner)")
    p.add_argument("--key", help="Sonar-Projektschlüssel (Pflicht, außer mit --lokal)")
    p.add_argument("--name", help="Projektname in SonarQube (Standard: Schlüssel bzw. Ordnername)")
    p.add_argument("--profil", choices=PROFILE, default="desktop", help="desktop oder web (web: zusätzlich Pysa)")
    p.add_argument("--lokal", action="store_true",
                   help="Arbeitsordner in ein eigenes Projekt '<schlüssel>-lokal' scannen (gemeinsamer Stand bleibt)")
    p.add_argument("--revision", help="Commit, der gescannt wird (sonar.scm.revision)")
    p.add_argument("--ohne-scm", action="store_true", help="Ordner ohne .git (git archive): SCM aus")
    p.add_argument("--host", default=os.environ.get("SONAR_HOST_URL") or SONAR_URL)
    p.add_argument("--berichte", help="Ordner für die Berichte der Werkzeuge (Standard: Temp-Ordner, danach gelöscht)")
    p.add_argument("--arbeit", help="Arbeitsordner des Scanners (Standard: im Berichte-Ordner)")
    p.add_argument("--metadaten", help="Pfad für report-task.txt (Standard: im Berichte-Ordner)")
    p.add_argument("--protokoll", help="Scanner-Ausgabe in diese Datei statt auf den Bildschirm")
    p.add_argument("--json", help="Ergebnis (Schritte, Dauer, Status) als JSON hierhin schreiben")
    p.add_argument("--pysonar", help="Pfad zu pysonar(.exe), falls nicht automatisch gefunden")
    p.add_argument("--ohne", default="", help="diese Werkzeuge auslassen (bandit,semgrep,pip-audit,pysa)")
    p.add_argument("--warten", action="store_true", help="warten, bis SonarQube die Analyse verarbeitet hat")
    p.add_argument("--zeitbudget", type=int,
                   help="Sekunden für den ganzen Lauf (Action: Job-Zeitlimit minus Einrichtung); die Werkzeuge "
                        f"bekommen höchstens so viel, dass {RESERVE_SCANNER} s für Scanner und Verarbeitung bleiben")
    p.add_argument("--nur-werkzeuge", action="store_true", help="nur die Werkzeuge, nicht scannen (zum Testen)")
    return p.parse_args(argv)


def fristen(budget: int | None, beginn: float) -> tuple[float | None, float | None]:
    """(Frist für die Werkzeuge, Frist für den ganzen Lauf) als time.monotonic()-Werte; ohne Budget keine."""
    if not budget:
        return None, None
    return beginn + max(budget - RESERVE_SCANNER, 0), beginn + budget


def projekt_bestimmen(a: argparse.Namespace, quelle: Path) -> tuple[str, str]:
    """(Schlüssel, Name). Mit --lokal immer '<schlüssel>-lokal' und '<name> (lokal)'."""
    if a.lokal:
        basis = a.key or sonar_schluessel(quelle.name)
        schluessel = basis if basis.endswith(LOKAL_ENDUNG) else basis + LOKAL_ENDUNG
        return schluessel, f"{a.name or quelle.name} (lokal)"
    if not a.key:
        raise RuntimeError("--key fehlt (oder --lokal für einen lokalen Scan).")
    if a.key.endswith(LOKAL_ENDUNG):
        raise RuntimeError(f"Schlüssel auf „{LOKAL_ENDUNG}“ sind lokalen Scans vorbehalten (--lokal).")
    return a.key, a.name or a.key


def main(argv: list[str] | None = None) -> int:
    konsole_utf8()
    a = argumente_lesen(argv)
    frist_werkzeuge, frist_ende = fristen(a.zeitbudget, time.monotonic())
    quelle = Path(a.quelle).resolve()
    ergebnis: dict = {"ergebnis": "abbruch", "grund": None, "schritte": []}
    try:
        if not quelle.is_dir():
            raise RuntimeError(f"Ordner gibt es nicht: {quelle}")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", (a.key or "x")) or (a.key or "x").isdigit():
            raise RuntimeError(f"Ungültiger Sonar-Schlüssel: {a.key!r}")
        schluessel, name = projekt_bestimmen(a, quelle)
        ergebnis.update(key=schluessel, name=name, profil=a.profil)
        token = None
        if not a.nur_werkzeuge:
            token = token_holen()
            wecken(token)
            token_pruefen(a.host, token)        # früh scheitern, bevor die Werkzeuge Minuten brauchen
    except RuntimeError as fehler:
        print(f"Abbruch: {fehler}", flush=True)
        ergebnis["grund"] = str(fehler)
        _json_schreiben(a.json, ergebnis)
        return 2

    if a.berichte:
        ziel, aufraeumen = Path(a.berichte).resolve(), False
        ziel.mkdir(parents=True, exist_ok=True)
    elif in_actions() and os.environ.get("RUNNER_TEMP"):
        ziel, aufraeumen = Path(os.environ["RUNNER_TEMP"]) / "code-pruefung", False
        ziel.mkdir(parents=True, exist_ok=True)
    else:
        ziel, aufraeumen = Path(tempfile.mkdtemp(prefix="pruefpipeline_")), True
    ohne = {w.strip().lower() for w in a.ohne.split(",") if w.strip()}

    print(f"Prüfpipeline {schluessel} („{name}“), Profil {a.profil}, Quelle {quelle}"
          + (f", Zeitbudget {dauer(a.zeitbudget)}" if a.zeitbudget else ""), flush=True)
    eigene = projekt_ausschluesse(quelle)
    if eigene:
        print(f"  Eigene Ausschlüsse ({AUSSCHLUSS_DATEI}): {', '.join(eigene)}", flush=True)
    schritte: list[Schritt] = []
    je_werkzeug: dict[str, Schritt] = {}
    try:
        for kennung, lauf in (("bandit", lambda: bandit_laufen(quelle, ziel, frist_werkzeuge)),
                              ("semgrep", lambda: semgrep_laufen(quelle, ziel, frist_werkzeuge)),
                              ("pip-audit", lambda: pip_audit_laufen(quelle, ziel, frist_werkzeuge)),
                              ("pysa", lambda: pysa_laufen(quelle, ziel, a.profil, frist_werkzeuge))):
            if kennung in ohne:
                s = Schritt(kennung, hinweis="mit --ohne ausgelassen")
            elif frist_werkzeuge is not None and frist_werkzeuge - time.monotonic() < WERKZEUG_MINDESTENS:
                s = Schritt(kennung, hinweis="Zeitbudget aufgebraucht — nicht gelaufen")
                hinweis(f"{kennung}: {s.hinweis}")
            else:
                print(f"- {kennung} …", flush=True)
                try:
                    s = lauf()
                except Exception as fehler:  # noqa: BLE001 — ein Werkzeug darf den Scan nie verhindern
                    s = Schritt(kennung, "fehler", hinweis=f"interner Fehler: {type(fehler).__name__}: {fehler}"[:300])
                text = f"  {s.name}: {s.status}, {dauer(s.dauer)}" + ("" if s.befunde is None else f", {s.befunde} Befunde")
                print(text, flush=True)
                if s.hinweis and s.status == "fehler":
                    hinweis(f"{s.name}: {s.hinweis}")
                elif s.hinweis:
                    print(f"  ({s.hinweis})", flush=True)
            schritte.append(s)
            je_werkzeug[kennung] = s

        if a.nur_werkzeuge:
            ergebnis.update(ergebnis="ok", berichte=str(ziel), werkzeuge=werkzeuge_angabe(je_werkzeug))
            return 0

        bandit = [s.bericht for s in schritte if s.bericht and s.bericht.endswith(".json")]
        sarif = [s.bericht for s in schritte if s.bericht and s.bericht.endswith(".sarif")]
        # Was nicht vollständig lief, darf seine offenen Befunde nicht verlieren (siehe „Fortschreiben“).
        # Nach langen Werkzeugläufen (Pysa) könnte SonarQube inzwischen eingeschlafen sein: noch einmal wecken
        if wecken(token) and not sonar_bereit(a.host, frist_ende):
            hinweis("SonarQube ist nach dem Wecken nicht hochgekommen.")
        try:
            mehr_bandit, mehr_sarif = fortschreiben(je_werkzeug, quelle, ziel, a.host, token, schluessel)
        except RuntimeError as fehler:
            hinweis(str(fehler))
            ergebnis.update(ergebnis="fehler", grund=str(fehler))
            return 1
        bandit += mehr_bandit
        sarif += mehr_sarif
        for s in schritte:
            if "fortgeschrieben" in s.hinweis:
                print(f"  {s.name}: {s.hinweis}", flush=True)
        # Erst nach dem Fortschreiben steht fest, wie jedes Werkzeug in diese Analyse eingeht.
        ergebnis["werkzeuge"] = werkzeuge_angabe(je_werkzeug)
        print(f"  Werkzeuge der Analyse: {ergebnis['werkzeuge']}", flush=True)
        pysonar = [a.pysonar] if a.pysonar else werkzeug("pysonar")
        scanner = Schritt("SonarQube-Scanner")
        if not pysonar:
            scanner.status, scanner.hinweis = "fehler", "pysonar nicht installiert"
            schritte.append(scanner)
            ergebnis.update(ergebnis="fehler", grund=scanner.hinweis)
            return 1
        arbeit = Path(a.arbeit) if a.arbeit else ziel / "scanner-arbeit"
        metadaten = Path(a.metadaten) if a.metadaten else ziel / "report-task.txt"
        befehl = [*pysonar, "--sonar-host-url", a.host, "--sonar-project-key", schluessel,
                  "--sonar-project-name", name, "--sonar-project-base-dir", str(quelle),
                  "--sonar-working-directory", str(arbeit), "--sonar-scanner-metadata-filepath", str(metadaten),
                  *java_argumente(),
                  *sonar_eigenschaften(bandit, sarif, a.revision, a.ohne_scm, ergebnis["werkzeuge"],
                                       ausschluesse(quelle))]
        for versuch in (1, 2):
            print("- SonarQube-Scanner …" + (f" (Ausgabe in {a.protokoll})" if a.protokoll else ""), flush=True)
            if in_actions():
                print("::group::Ausgabe des SonarQube-Scanners", flush=True)
            beginn = time.monotonic()
            umgebung = _umgebung(SONAR_TOKEN=token)
            grenze = restzeit("scanner", frist_ende)
            try:
                if a.protokoll:
                    with open(a.protokoll, "w", encoding="utf-8") as log:
                        code = laufen_mit_grenze(befehl, quelle, grenze, umgebung, log)
                else:
                    code = laufen_mit_grenze(befehl, quelle, grenze, umgebung)
            except OSError as fehler:
                code = f"nicht startbar ({fehler})"
            finally:
                if in_actions():
                    print("::endgroup::", flush=True)
            scanner.dauer = time.monotonic() - beginn
            schritte.append(scanner)
            if code != 0:
                scanner.status = "fehler"
                scanner.hinweis = (f"nach {dauer(grenze)} abgebrochen" if code is None else
                                   str(code) if isinstance(code, str) else
                                   f"Exit {code}" + (f": {letzte_zeilen(Path(a.protokoll), 3)}" if a.protokoll else ""))
                # Schnell gescheitert (z. B. „Error while fetching the analysis version“): SonarQube war beim Hochladen
                # gerade weg (Neustart nach OOM) — einmal warten, bis es wieder UP ist, und neu hochladen.
                if (versuch == 1 and isinstance(code, int) and scanner.dauer < 180
                        and sonar_bereit(a.host, frist_ende)):
                    scanner.hinweis += " — SonarQube nicht erreichbar, Upload wird wiederholt"
                    print(f"  {scanner.hinweis}", flush=True)
                    scanner = Schritt("SonarQube-Scanner (2. Versuch)")
                    continue
                ergebnis.update(ergebnis="fehler", grund=f"Scanner: {scanner.hinweis}")
                return 1
            scanner.status = "ok"
            bericht = bericht_lesen(metadaten)
            ergebnis.update(ce_task=bericht.get("ceTaskId"), dashboard=bericht.get("dashboardUrl"))
            if not a.warten:
                break
            if a.warten:
                server = Schritt("SonarQube-Verarbeitung")
                schritte.append(server)
                if not bericht.get("ceTaskId"):
                    server.status, server.hinweis = "fehler", "report-task.txt ohne ceTaskId"
                    ergebnis.update(ergebnis="fehler", grund=server.hinweis)
                    return 1
                beginn = time.monotonic()
                status, meldung = server_warten(a.host, token, bericht["ceTaskId"], frist_ende)
                server.dauer = time.monotonic() - beginn
                ergebnis.update(ce_status=status, ce_fehler=meldung)
                if status != "SUCCESS":
                    server.status, server.hinweis = "fehler", f"{status}" + (f": {meldung}" if meldung else "")
                    if versuch == 1 and voruebergehend(status, meldung) and sonar_bereit(a.host, frist_ende):
                        server.hinweis += " — SonarQube war neu gestartet, Analyse wird wiederholt"
                        print(f"  {server.hinweis}", flush=True)
                        scanner = Schritt("SonarQube-Scanner (2. Versuch)")
                        continue
                    ergebnis.update(ergebnis="fehler", grund=f"SonarQube-Verarbeitung {server.hinweis}")
                    return 1
                server.status = "ok"
                break
        ergebnis["ergebnis"] = "ok"
        return 0
    finally:
        ergebnis["schritte"] = [asdict(s) for s in schritte]
        if schritte:
            text = zusammenfassung(schritte, f"Prüfpipeline {ergebnis.get('key')} ({ergebnis.get('profil')})")
            print("\n" + text, flush=True)
            if ergebnis.get("dashboard"):
                print(f"Ergebnis: {ergebnis['dashboard']}", flush=True)
            if in_actions() and os.environ.get("GITHUB_STEP_SUMMARY"):
                with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as datei:
                    datei.write(text)
        _json_schreiben(a.json, ergebnis)
        if aufraeumen:
            shutil.rmtree(ziel, ignore_errors=True)


def _json_schreiben(pfad: str | None, ergebnis: dict) -> None:
    if pfad:
        Path(pfad).write_text(json.dumps(ergebnis, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
