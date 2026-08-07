"""
Lab 11 — Helper Utilities
"""
import asyncio
from google.genai import types


def _is_quota_error(exc: BaseException) -> bool:
    name = type(exc).__name__
    msg = str(exc).lower()
    return (
        "ResourceExhausted" in name
        or "429" in str(exc)
        or "resource_exhausted" in msg
        or "resource has been exhausted" in msg
    )


async def chat_with_agent(
    agent,
    runner,
    user_message: str,
    session_id=None,
    *,
    retries: int = 3,
    base_delay: float = 8.0,
):
    """Send a message to the agent and get the response.

    Retries with backoff on Gemini 429 RESOURCE_EXHAUSTED (free-tier quota).

    Args:
        agent: The LlmAgent instance
        runner: The InMemoryRunner instance
        user_message: Plain text message to send
        session_id: Optional session ID to continue a conversation
        retries: Extra attempts after the first failure
        base_delay: Seconds to wait before first retry (doubles each time)

    Returns:
        Tuple of (response_text, session)
    """
    user_id = "student"
    app_name = runner.app_name

    session = None
    if session_id is not None:
        try:
            session = await runner.session_service.get_session(
                app_name=app_name, user_id=user_id, session_id=session_id
            )
        except (ValueError, KeyError):
            pass

    if session is None:
        try:
            session = await runner.session_service.create_session(
                app_name=app_name, user_id=user_id
            )
        except Exception:
            session = await runner.session_service.create_session(
                app_name=app_name, user_id=user_id
            )

    content = types.Content(
        role="user",
        parts=[types.Part.from_text(text=user_message)],
    )

    last_err: BaseException | None = None
    for attempt in range(retries + 1):
        try:
            final_response = ""
            async for event in runner.run_async(
                user_id=user_id, session_id=session.id, new_message=content
            ):
                if hasattr(event, "content") and event.content and event.content.parts:
                    for part in event.content.parts:
                        if hasattr(part, "text") and part.text:
                            final_response += part.text
            return final_response, session
        except Exception as e:
            last_err = e
            if _is_quota_error(e) and attempt < retries:
                wait = base_delay * (2 ** attempt)
                print(
                    f"  [quota 429] wait {wait:.0f}s then retry "
                    f"({attempt + 1}/{retries})…"
                )
                await asyncio.sleep(wait)
                continue
            raise

    assert last_err is not None
    raise last_err
