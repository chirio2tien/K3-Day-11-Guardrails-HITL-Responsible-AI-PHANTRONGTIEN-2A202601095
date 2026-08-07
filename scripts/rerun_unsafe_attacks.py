"""Re-run Part B attacks against UNSAFE agent only; refresh JSON evidence."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env", override=True)

from core.config import setup_api_key, get_llm_provider  # noqa: E402
from agents.agent import create_unsafe_agent  # noqa: E402
from attacks.attacks import (  # noqa: E402
    run_attacks,
    save_attack_results,
    attack_result_path,
)


async def main() -> None:
    setup_api_key()
    print(f"Provider: {get_llm_provider()}")
    agent, runner = create_unsafe_agent()
    results = await run_attacks(
        agent, runner, target_name="unsafe", save_json=True
    )

    # Keep guards half of attack_results.json if present; refresh unsafe half.
    combined_path = ROOT / "outputs" / "attack_results.json"
    guards = []
    if combined_path.is_file():
        old = json.loads(combined_path.read_text(encoding="utf-8"))
        guards = old.get("guards_attacks") or []

    save_attack_results(
        unsafe_results=results,
        guards_results=guards,
        ai_attacks=None,
        student_id="2A202601095",
    )

    leaked = [r for r in results if r.get("leaked")]
    refuse = [r for r in results if r.get("layer") == "model_refuse"]
    print("\n===== UNSAFE RETEST SUMMARY =====")
    print(f"Total: {len(results)}")
    print(f"Leaked: {len(leaked)} → ids {[r['id'] for r in leaked]}")
    print(f"Model refuse: {len(refuse)} → ids {[r['id'] for r in refuse]}")
    for r in results:
        flag = "LEAK" if r.get("leaked") else (r.get("layer") or "pass")
        print(f"  #{r['id']:02d} [{flag}] {r.get('category')}")
    print(f"Saved → {attack_result_path('unsafe')}")
    print(f"Updated → {combined_path}")


if __name__ == "__main__":
    asyncio.run(main())
