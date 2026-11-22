import pytest
from common.config import PERSONAS, MFA_DEADLINE_DAYS, IAM_PATH

def test_personas_cover_the_deck_roles():
    assert set(PERSONAS) == {"developer", "devops", "security-admin", "finance", "product", "hr", "executive"}

def test_every_persona_maps_to_one_of_three_groups():
    assert set(PERSONAS.values()) == {"TechTeam", "BusinessTeam", "SecurityTeam"}

@pytest.mark.parametrize("persona,group", [("developer", "TechTeam"), ("devops", "TechTeam"),
    ("security-admin", "SecurityTeam"), ("finance", "BusinessTeam"), ("executive", "BusinessTeam")])
def test_slide_4_1_and_4_2_mapping(persona, group):
    assert PERSONAS[persona] == group

def test_path_and_deadline_sane():
    assert IAM_PATH.startswith("/") and IAM_PATH.endswith("/")
    assert 1 <= MFA_DEADLINE_DAYS <= 30
