#!/usr/bin/env python3
"""Onboard the Nimbus roster through the web console, the same way a person would.
Usage:  ADMIN_PASSWORD=... python3 scripts/seed_employees.py https://<ip>:8443 [first|rest|all]
Signs in like an administrator: password, then the 6 digit code from your authenticator app (it asks for it, or reads TOTP_CODE). It prints each one time console password ONCE. Needs: pip install requests"""
import os, re, sys
import requests

ROSTER = [("james", "James Smith", "developer"), ("olivia", "Olivia Brown", "developer"),
          ("michael", "Michael Davis", "devops"), ("sarah", "Sarah Wilson", "devops"),
          ("david", "David Miller", "security-admin"), ("jennifer", "Jennifer Taylor", "finance"),
          ("robert", "Robert Anderson", "product"), ("emily", "Emily Thomas", "hr"),
          ("william", "William Moore", "executive"), ("jessica", "Jessica Martin", "executive")]


def main(base, which="rest", verify=False):
    s = requests.Session(); s.verify = verify
    if not verify:
        requests.packages.urllib3.disable_warnings()          # self-signed lab certificate
    pw = os.environ.get("ADMIN_PASSWORD") or sys.exit("set ADMIN_PASSWORD")
    r = s.post(base + "/login", data={"username": "admin", "password": pw}, allow_redirects=False)
    if r.status_code != 302:
        sys.exit("login failed")
    if "/mfa" in r.headers["Location"]:                       # Cognito asks for the second factor
        code = os.environ.get("TOTP_CODE") or input("6 digit code from your authenticator app: ").strip()
        r = s.post(base + "/mfa", data={"code": code}, allow_redirects=False)
        if r.status_code != 302:
            sys.exit("the code was not accepted")
    people = {"first": ROSTER[:3], "rest": ROSTER[3:], "all": ROSTER}[which]
    for user, name, persona in people:
        page = s.get(base + "/onboard").text
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        r = s.post(base + "/onboard", data={"csrf": csrf, "username": user, "full_name": name,
                   "email": f"{user}@example.com", "persona": persona, "console_access": "on"})
        m = re.search(r'<code class="pw">([^<]+)</code>', r.text)
        if m: print(f"{user:10} onboarded  one-time password: {m.group(1)}")
        else:
            err = re.search(r'class="msg bad">([^<]+)', r.text)
            print(f"{user:10} NOT onboarded: {err.group(1) if err else 'unknown error'}")


if __name__ == "__main__":
    if len(sys.argv) < 2: sys.exit(__doc__)
    main(sys.argv[1].rstrip("/"), sys.argv[2] if len(sys.argv) > 2 else "rest")
