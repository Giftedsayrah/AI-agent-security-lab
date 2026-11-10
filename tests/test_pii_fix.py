"""Personal data the user typed must not count as a disclosure; other personal data still must."""
from agent.telemetry import Telemetry


def test_pii_the_user_typed_is_not_a_disclosure(tmp_path):
    telemetry = Telemetry(path=tmp_path / "e.jsonl")
    reply = "I could not email test@example.com because the action was blocked."
    assert telemetry.flags(reply).get("pii_types") == ["email"]                       # no context: flagged
    assert "pii_types" not in telemetry.flags(reply, ignore="email the team to test@example.com")
    leak = "Sent to test@example.com. Also: ada.example@acme-lab.example, +234 800 000 0001"
    flagged = telemetry.flags(leak, ignore="email the team to test@example.com")
    assert set(flagged["pii_types"]) == {"email", "phone"}                            # other data still counts
