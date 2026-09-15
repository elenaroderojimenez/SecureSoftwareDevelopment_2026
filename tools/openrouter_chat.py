"""Interactive study chat using OpenRouter."""

import os
import re

from openai import OpenAI


MAX_INPUT_CHARS = 100
MAX_HISTORY_MESSAGES = 20
MAX_COMPLETION_TOKENS = 500

SYSTEM_MESSAGE = {
    "role": "system",
    "content": (
        "You are a secure software development tutor. Explain defensive "
        "concepts only. Do not claim access to private application data."
    ),
}

SECRET_PATTERNS = [
    (re.compile(r"(?i)(api[_-]?key\s*[=:]\s*)[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(password\s*[=:]\s*)[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(token\s*[=:]\s*)[^\s,;]+"), r"\1[REDACTED]"),
]


def redact(text):
    """Replace common credential patterns before sending text."""
    for pattern, replacement in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _validate_message(message):
    if not isinstance(message, str) or not message.strip():
        raise ValueError("The message must be a non-empty string.")
    return message.strip()[:MAX_INPUT_CHARS]


def ask_openrouter(message, conversation=None, client=None):
    """Send one message and return the assistant's text response."""
    message = redact(_validate_message(message))
    history = conversation if isinstance(conversation, list) else []
    messages = [SYSTEM_MESSAGE, *history[-MAX_HISTORY_MESSAGES:]]
    messages.append({"role": "user", "content": message})

    if client is None:
        client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=os.environ["OPENROUTER_API_KEY"],
        )

    try:
        response = client.chat.completions.create(
            model=os.getenv("OPENROUTER_MODEL", "openrouter/free"),
            messages=messages,
            max_completion_tokens=MAX_COMPLETION_TOKENS,
        )
    except Exception as error:
        raise RuntimeError("The chatbot request failed.") from error
    content = response.choices[0].message.content
    if not isinstance(content, str) or not content.strip():
        raise ValueError("The model returned an empty response.")
    return content.strip()


def run_interactive_chat():
    """Read questions until the user exits."""
    conversation = []
    print("Secure study chat. Type /exit or /quit to finish.")
    while True:
        try:
            message = input("You: ")
        except EOFError:
            print()
            break
        if message.strip().lower() in {"/exit", "/quit"}:
            break
        try:
            answer = ask_openrouter(message, conversation=conversation)
        except KeyError:
            print("Error: OPENROUTER_API_KEY is not configured.")
            continue
        except (ValueError, RuntimeError):
            print("Error: chatbot request failed.")
            continue
        print(f"Assistant: {answer}")
        conversation.extend(
            [
                {
                    "role": "user",
                    "content": redact(message.strip())[:MAX_INPUT_CHARS],
                },
                {"role": "assistant", "content": answer},
            ]
        )
        del conversation[:-MAX_HISTORY_MESSAGES]


if __name__ == "__main__":
    run_interactive_chat()
