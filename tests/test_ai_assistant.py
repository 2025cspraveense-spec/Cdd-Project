import pytest

from app.ai_assistant import AIAssistant, AIConsentRequiredError
from app.db import DatabaseClient


def test_groq_provider_uses_chat_api_and_configured_model(monkeypatch):
    calls = []

    class FakeResponse:
        def raise_for_status(self):
            return None

        @staticmethod
        def json():
            return {"choices": [{"message": {"content": "READY"}}]}

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse()

    monkeypatch.setattr("app.ai_assistant.requests.post", fake_post)
    assistant = AIAssistant(
        database=None,
        api_key="test-groq-key",
        model="openai/gpt-oss-20b",
        provider="groq",
    )

    assert assistant._generate("Synthetic prompt") == "READY"
    url, request = calls[0]
    assert url == "https://api.groq.com/openai/v1/chat/completions"
    assert request["headers"]["Authorization"] == "Bearer test-groq-key"
    assert request["json"]["model"] == "openai/gpt-oss-20b"
    assert request["json"]["messages"][-1] == {
        "role": "user",
        "content": "Synthetic prompt",
    }


def test_ai_requires_consent_before_provider_call():
    calls = []
    database = DatabaseClient(use_mock=True, db_name="test_ai_consent")
    assistant = AIAssistant(database, None, "test-model", generator=lambda prompt: calls.append(prompt) or "answer")

    with pytest.raises(AIConsentRequiredError):
        assistant.respond(
            user_id="user-1",
            scan_id="scan-1",
            task="summary",
            report={"status": "COMPLETED", "findings": []},
            consent=False,
        )

    assert calls == []
    database.close()


def test_ai_sends_only_redacted_metadata_and_persists_cached_history():
    raw_secret = "".join(["AK", "IA", "1234567890ABCDEF"])
    calls = []
    database = DatabaseClient(use_mock=True, db_name="test_ai_persistence")

    def fake_generator(prompt):
        calls.append(prompt)
        return f"Suggested review for {raw_secret}; this has not been verified."

    assistant = AIAssistant(database, None, "test-model", generator=fake_generator)
    report = {
        "status": "COMPLETED",
        "grade": "F",
        "scores": {"final_score": 100, "severity_counts": {"critical": 1}},
        "findings": [{
            "fingerprint": "finding-1",
            "rule_id": "SAST-TEST",
            "engine_name": "SASTEngine",
            "category": "Injection",
            "severity": "critical",
            "description": f"Detected {raw_secret}",
            "raw_secret": raw_secret,
            "match_content": f"code = '{raw_secret}'",
        }],
    }

    first = assistant.respond(
        user_id="user-1",
        scan_id="scan-1",
        task="explain",
        report=report,
        finding=report["findings"][0],
        consent=True,
    )
    second = assistant.respond(
        user_id="user-1",
        scan_id="scan-1",
        task="explain",
        report=report,
        finding=report["findings"][0],
        consent=True,
    )
    other_scan = assistant.respond(
        user_id="user-1",
        scan_id="scan-2",
        task="explain",
        report=report,
        finding=report["findings"][0],
        consent=True,
    )
    chat = assistant.respond(
        user_id="user-1",
        scan_id="scan-1",
        task="chat",
        report=report,
        consent=True,
        question=f"Does this value need rotation: {raw_secret}?",
    )

    assert len(calls) == 3
    assert raw_secret not in calls[0]
    assert "match_content" not in calls[0]
    assert raw_secret not in first["response"]
    assert raw_secret not in calls[2]
    assert raw_secret not in chat["question"]
    assert isinstance(first["generation_time_ms"], int)
    assert first["generation_time_ms"] >= 0
    assert second["cached"] is True
    assert second["generation_time_ms"] == first["generation_time_ms"]
    assert other_scan["cached"] is False
    assert chat["expires_at"] > chat["created_at"]
    assert len(database.list_ai_history("user-1", "scan-1")) == 2
    assert len(database.list_ai_history("user-1", "scan-2")) == 1
    assert database.list_ai_history("user-2", "scan-1") == []
    database.close()


def test_ai_context_bounds_large_scans_and_omits_other_findings_for_actions():
    assistant = AIAssistant(
        database=None,
        api_key="test-key",
        model="test-model",
        generator=lambda prompt: "answer",
    )
    findings = [
        {
            "rule_id": f"rule-{index}-" + ("x" * 1000),
            "engine_name": "SASTEngine",
            "category": "Security",
            "severity": "high",
            "description": "d" * 1000,
            "match_content": "source evidence must not be sent",
        }
        for index in range(308)
    ]
    report = {
        "status": "COMPLETED",
        "scores": {"final_score": 100, "severity_counts": {"high": 308}},
        "findings": findings,
    }

    explain_context = assistant._context("explain", report, findings[0], None)
    summary_context = assistant._context("summary", report, None, None)

    assert explain_context["scan"]["finding_count"] == 308
    assert "findings" not in explain_context["scan"]
    assert len(explain_context["finding"]["description"]) == 400
    assert len(summary_context["scan"]["findings"]) == assistant.MAX_CHAT_FINDINGS
    assert summary_context["scan"]["additional_findings"] == 296
    assert len(summary_context["scan"]["findings"][0]["rule_id"]) == 120
    assert "match_content" not in str(summary_context)
    assert len(str(summary_context)) < 10000
