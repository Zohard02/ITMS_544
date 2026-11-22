"""Organisation model for Nimbus Analytics (from the IAM deck, Module 4).

To grow from 10 to 100 people you change NOTHING here: you add rows in the
web form. To add a persona (e.g. Contractor) add one line below + one IAM group.
"""
IAM_PATH = "/nimbus/"            # every identity this app manages lives under this path
SERVICE_TAG = "lab02"   # value of the managed-by tag

# persona -> IAM group  (Module 4.1 / 4.2)
PERSONAS = {
    "developer":      "TechTeam",
    "devops":         "TechTeam",
    "security-admin": "SecurityTeam",
    "finance":        "BusinessTeam",
    "product":        "BusinessTeam",
    "hr":             "BusinessTeam",
    "executive":      "BusinessTeam",
}
MFA_DEADLINE_DAYS = 7
