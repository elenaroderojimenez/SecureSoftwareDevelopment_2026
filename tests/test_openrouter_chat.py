from types import SimpleNamespace

import pytest

from tools import openrouter_chat


class FakeClient:
    def __init__(self, content="Safe answer"):
        self.calls = []
        self.content = content
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content=self.content)
                )
            ]
        )


def test_api_key_is_required_from_environment(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

    with pytest.raises(KeyError):
        openrouter_chat.ask_openrouter("hello")


def test_openai_client_receives_environment_key(monkeypatch):
    captured = {}
    client = FakeClient()

    def fake_openai(**kwargs):
        captured.update(kwargs)
        return client

    monkeypatch.setenv("OPENROUTER_API_KEY", "environment-key")
    monkeypatch.setattr(openrouter_chat, "OpenAI", fake_openai)

    openrouter_chat.ask_openrouter("hello")

    assert captured == {
        "base_url": "https://openrouter.ai/api/v1",
        "api_key": "environment-key",
    }


@pytest.mark.parametrize("message", ["", "   "])
def test_empty_messages_are_rejected_before_provider_call(message):
    with pytest.raises(ValueError):
        openrouter_chat.ask_openrouter(message, client=FakeClient())


def test_message_is_limited_like_the_lecture_example():
    client = FakeClient()
    message = "x" * 150

    openrouter_chat.ask_openrouter(message, client=client)

    sent_message = client.calls[0]["messages"][-1]["content"]
    assert len(sent_message) == openrouter_chat.MAX_INPUT_CHARS


def test_likely_secrets_are_redacted_before_sending():
    client = FakeClient()

    openrouter_chat.ask_openrouter(
        "password=SuperSecret123 api_key=abc123 token=private-token",
        client=client,
    )

    sent_message = client.calls[0]["messages"][-1]["content"]
    assert "SuperSecret123" not in sent_message
    assert "abc123" not in sent_message
    assert "private-token" not in sent_message
    assert "[REDACTED]" in sent_message


def test_request_uses_openrouter_sdk_shape_and_fixed_security_context(monkeypatch):
    monkeypatch.setenv("OPENROUTER_MODEL", "openrouter/free")
    client = FakeClient(" Safe answer ")

    result = openrouter_chat.ask_openrouter(
        "How do I prevent SQL injection?",
        conversation=[
            {"role": "user", "content": "What is SQL injection?"},
            {"role": "assistant", "content": "It is an injection flaw."},
        ],
        client=client,
    )

    assert result == "Safe answer"
    call = client.calls[0]
    assert call["model"] == "openrouter/free"
    assert call["max_completion_tokens"] == 500
    assert [item["role"] for item in call["messages"]] == [
        "system",
        "user",
        "assistant",
        "user",
    ]


def test_provider_error_is_handled_without_returning_provider_details():
    class FailingClient:
        chat = SimpleNamespace(
            completions=SimpleNamespace(
                create=lambda **kwargs: (_ for _ in ()).throw(
                    RuntimeError("private provider details")
                )
            )
        )

    with pytest.raises(RuntimeError) as error:
        openrouter_chat.ask_openrouter("hello", client=FailingClient())

    assert str(error.value) == "The chatbot request failed."
    assert "private provider details" not in str(error.value)


def test_interactive_loop_keeps_history_and_exits(monkeypatch, capsys):
    user_inputs = iter(["first question", "second question", "/exit"])
    calls = []

    monkeypatch.setattr("builtins.input", lambda prompt: next(user_inputs))

    def fake_ask(message, conversation=None, client=None):
        calls.append((message, list(conversation)))
        return f"answer to {message}"

    monkeypatch.setattr(openrouter_chat, "ask_openrouter", fake_ask)
    openrouter_chat.run_interactive_chat()

    assert [call[0] for call in calls] == ["first question", "second question"]
    assert calls[0][1] == []
    assert calls[1][1] == [
        {"role": "user", "content": "first question"},
        {"role": "assistant", "content": "answer to first question"},
    ]
    assert "Assistant: answer to second question" in capsys.readouterr().out
