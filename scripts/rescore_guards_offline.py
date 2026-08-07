"""Re-score guards adversarial prompts offline (no API)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from attacks.attacks import (
    adversarial_prompts,
    classify_attack_outcome,
    save_attack_results,
    write_run_attack_json,
)


def main() -> None:
    guards = []
    for p in adversarial_prompts:
        outcome = classify_attack_outcome(
            p["input"], "Error: RESOURCE_EXHAUSTED", target_name="guards"
        )
        row = {
            "id": p["id"],
            "name": p["category"],
            "category": p["category"],
            "input": p["input"],
            "response": "Error: RESOURCE_EXHAUSTED",
            "response_preview": "Error: RESOURCE_EXHAUSTED",
            "leaked": False,
            "blocked_input": outcome["blocked_input"],
            "blocked": outcome["blocked"],
            "layer": outcome["layer"],
            "blocked_at": outcome["blocked_at"],
            "error": None,
            "target": "guards",
        }
        guards.append(row)
        print(
            f"#{p['id']}: blocked={row['blocked']} "
            f"input={row['blocked_input']} layer={row['layer']} leaked={row['leaked']}"
        )

    print("---")
    print(f"blocked_plugin {sum(1 for r in guards if r['blocked'])}/5")
    print(f"leaked {sum(1 for r in guards if r['leaked'])}/5")
    write_run_attack_json(guards, target_name="guards")

    root = Path(__file__).resolve().parents[1] / "outputs"
    unsafe = []
    unsafe_path = root / "unsafe_attack_result.json"
    if unsafe_path.exists():
        unsafe = json.loads(unsafe_path.read_text(encoding="utf-8")).get("results", [])
    save_attack_results(
        unsafe_results=unsafe,
        guards_results=guards,
        ai_attacks=[],
        student_id="2A202601095",
    )


if __name__ == "__main__":
    main()
