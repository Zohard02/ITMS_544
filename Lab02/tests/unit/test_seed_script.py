"""The seed script must onboard the same ten person roster the deck describes, using valid personas."""
import importlib.util, os, re
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
spec = importlib.util.spec_from_file_location("seed", f"{ROOT}/scripts/seed_employees.py")
seed = importlib.util.module_from_spec(spec); spec.loader.exec_module(seed)
from common import config

def test_roster_has_ten_unique_people_with_valid_personas():
    names = [r[0] for r in seed.ROSTER]
    assert len(names) == 10 and len(set(names)) == 10
    assert all(re.fullmatch(r"[a-z][a-z0-9._-]{2,31}", n) for n in names)
    assert {r[2] for r in seed.ROSTER} <= set(config.PERSONAS)

def test_first_and_rest_split_covers_the_roster():
    assert seed.ROSTER[:3] + seed.ROSTER[3:] == seed.ROSTER
