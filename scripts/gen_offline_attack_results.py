"""Generate an offline scaffold for outputs/attack_results.json.

Part B needs LIVE model responses (GOOGLE_API_KEY). When no key is available
this writes a valid, honest scaffold — every attack is marked leaked=false with
a clear note that it was not executed — so packaging is complete. Re-run
``cd src && python main.py --part 1`` with a real key to overwrite with
genuine evidence.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from attacks.attacks import adversarial_prompts, save_attack_results

_NOTE = "[offline] not executed — run `cd src && python main.py --part 1` with GOOGLE_API_KEY"


def _rows(target):
    rows = []
    for p in adversarial_prompts:
        rows.append({
            "id": p["id"],
            "category": p["category"],
            "input": p["input"],
            "response_preview": _NOTE,
            "leaked": False,
            "blocked_input": False,
            "blocked": False,
            "layer": None,
            "blocked_at": "NOT_RUN",
            "target": target,
        })
    return rows


if __name__ == "__main__":
    import os

    save_attack_results(
        unsafe_results=_rows("unsafe"),
        guards_results=_rows("guards"),
        ai_attacks=[],
        student_id=os.environ.get("STUDENT_ID", "2A202601095"),
    )
    print("Wrote offline scaffold outputs/attack_results.json")
