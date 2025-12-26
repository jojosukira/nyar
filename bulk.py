#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pip install google-api-python-client google-auth google-auth-oauthlib requests


import os, re, sys, csv
from pathlib import Path
from urllib.parse import urljoin

import requests
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

SCOPES = [
    "https://www.googleapis.com/auth/webmasters",
    "https://www.googleapis.com/auth/siteverification",
]

DOMAINS_FILE  = "domain.txt"
CLIENT_SECRET = "client_secret.json"
TOKEN_STORE   = "token.json"
TOKENS_DIR    = Path("tokens")
REPORT_CSV    = Path("tokens_report.csv")

def build_creds():
    c = None
    if os.path.exists(TOKEN_STORE):
        c = Credentials.from_authorized_user_file(TOKEN_STORE, SCOPES)
    if not c or not c.valid:
        if c and c.expired and c.refresh_token:
            c.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET, SCOPES)
            c = flow.run_local_server(port=0)
        Path(TOKEN_STORE).write_text(c.to_json(), encoding="utf-8")
    return c

def norm_url(s: str) -> str:
    s = s.strip()
    if not s: return ""
    if not re.match(r"^https?://", s, flags=re.I):
        s = "https://" + s
    if not s.endswith("/"):
        s += "/"
    return s

def read_sites():
    with open(DOMAINS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            u = norm_url(line)
            if u: yield u

if __name__ == "__main__":
    if not os.path.exists(DOMAINS_FILE): sys.exit(f"[!] {DOMAINS_FILE} tidak ditemukan.")
    if not os.path.exists(CLIENT_SECRET): sys.exit(f"[!] {CLIENT_SECRET} tidak ditemukan.")
    TOKENS_DIR.mkdir(exist_ok=True)

    creds = build_creds()
    gsc = build("searchconsole", "v1", credentials=creds)
    sv  = build("siteVerification", "v1", credentials=creds)

    sites = list(read_sites())
    if not sites: sys.exit("[!] domain.txt kosong.")

    print(f"[i] Total sites: {len(sites)}")

    # siapkan laporan
    with open(REPORT_CSV, "w", newline="", encoding="utf-8") as rep:
        w = csv.writer(rep); w.writerow(["site_url", "token_filename", "target_file_url", "verify_status", "note"])

        for site in sites:
            print(f"\n=== {site} ===")

            # 1) ADD property (idempotent)
            try:
                gsc.sites().add(siteUrl=site).execute()
                print(f"[+] Add OK: {site}")
            except Exception as e:
                print(f"[!] Add fail ({site}): {e}")

            token = None
            file_url = None

            # 2) GET FILE token (untuk catatan; diasumsikan file sudah ada di hosting)
            try:
                body = {"site": {"type": "SITE", "identifier": site}, "verificationMethod": "FILE"}
                token = sv.webResource().getToken(body=body).execute()["token"]  # e.g., googleXXXX.html
                content_line = f"google-site-verification: {token}\n"
                (TOKENS_DIR / token).write_text(content_line, encoding="utf-8")
                file_url = urljoin(site, token)
                print(f"[i] Token filename: {token}")
                print(f"    Target file URL: {file_url}")
            except Exception as e:
                print(f"[!] getToken fail ({site}): {e}")

            # 3) Langsung VERIFY (tanpa pause)
            #    Kita langsung tembak verifikasi; bila file benar2 sudah ada, ini akan sukses.
            try:
                resp = sv.webResource().insert(
                    verificationMethod="FILE",
                    body={"verificationMethod": "FILE", "site": {"type": "SITE", "identifier": site}},
                ).execute()
                owners = ", ".join(resp.get("owners", [])) or "-"
                print(f"[✓] Verified: {site} | Owners: {owners}")
                w.writerow([site, token or "-", file_url or "-", "VERIFIED", ""])
            except Exception as e:
                # Tambahan info cepat supaya tahu kenapa gagal
                note = str(e)
                http_note = ""
                if file_url:
                    try:
                        r = requests.get(file_url, timeout=10, allow_redirects=True)
                        http_note = f"HTTP={r.status_code} len={len(r.text)}"
                    except Exception as ee:
                        http_note = f"HTTP request error: {ee}"
                print(f"[x] Verify failed: {e}")
                if http_note:
                    print(f"    [hint] {http_note}")
                w.writerow([site, token or "-", file_url or "-", "FAILED", f"{note} | {http_note}"])
                # lanjut ke domain berikutnya tanpa berhenti

    print(f"\n[Report] {REPORT_CSV} dibuat. Selesai.")
