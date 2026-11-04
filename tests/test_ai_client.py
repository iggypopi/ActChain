# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

import builtins
import json
from types import SimpleNamespace

import pytest

import actchain.ai.client as ai_client
from actchain.ai.client import (
    AIAnalysisError,
    AIAuthenticationFailed,
    AIBatchRefused,
    AIBudgetExhausted,
    AIClient,
)

SCHEMA = {'type': 'object', 'properties': {}, 'required': [], 'additionalProperties': False}


class FakeMessages:
    def __init__(self, owner):
        self._owner = owner

    def create(self, **kwargs):
        self._owner.kwargs = kwargs
        result = self._owner.result
        if isinstance(result, Exception):
            raise result
        return result


class FakeAnthropicClient:
    """Stand-in for anthropic.Anthropic: records kwargs, replays one result."""

    def __init__(self, result=None):
        self.kwargs = None
        self.result = result
        self.messages = FakeMessages(self)


def text_response(payload):
    return SimpleNamespace(
        stop_reason='end_turn',
        stop_details=None,
        content=[SimpleNamespace(type='text', text=json.dumps(payload))],
    )


def make_client(result=None, calls_made=0, model='claude-test-1'):
    client = AIClient.__new__(AIClient)
    client._model = model
    client._calls_made = calls_made
    client._client = FakeAnthropicClient(result)
    return client


def dummy_sdk():
    """A fake anthropic module exposing the exception classes AIClient maps."""

    class AuthenticationError(Exception):
        pass

    class RateLimitError(Exception):
        pass

    class APIStatusError(Exception):
        def __init__(self, status_code):
            super().__init__(f'HTTP {status_code} with a secret body')
            self.status_code = status_code

    class APIConnectionError(Exception):
        pass

    return SimpleNamespace(
        AuthenticationError=AuthenticationError,
        RateLimitError=RateLimitError,
        APIStatusError=APIStatusError,
        APIConnectionError=APIConnectionError,
    )


class TestModelValidation:
    def test_valid_model_accepted(self, monkeypatch):
        monkeypatch.setattr(AIClient, '_create_client', lambda self: FakeAnthropicClient())
        client = AIClient('claude-opus-5-5')
        assert client.calls_made == 0

    @pytest.mark.parametrize('model', [
        'gpt-4o',
        'claude',
        '',
        'claude-OPUS',
        'claude-x y',
        None,
    ])
    def test_invalid_model_rejected(self, model):
        with pytest.raises(AIAnalysisError, match='Invalid AI model name'):
            AIClient(model)


class TestLazyImport:
    def test_missing_extra_names_the_install_command(self, monkeypatch):
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == 'anthropic':
                raise ImportError('No module named anthropic')
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(ai_client, 'anthropic', None)
        monkeypatch.setattr(builtins, '__import__', fake_import)
        with pytest.raises(AIAnalysisError, match=r'pip install "actchain\[ai\]"'):
            AIClient('claude-opus-5-5')


class TestBudget:
    def test_budget_enforced_and_counter_increments(self, monkeypatch):
        monkeypatch.setattr(ai_client, 'AI_MAX_CALLS_PER_SCAN', 1)
        client = make_client(result=text_response({'ok': True}))
        assert client.structured_request('s', 'u', SCHEMA, 'medium') == {'ok': True}
        assert client.calls_made == 1
        with pytest.raises(AIBudgetExhausted, match='AI call budget exhausted'):
            client.structured_request('s', 'u', SCHEMA, 'medium')
        assert client.calls_made == 1  # a budget rejection is not an attempt

    def test_refused_request_still_consumes_budget(self):
        # The budget counts attempts, so a refusal still increments it.
        response = SimpleNamespace(stop_reason='refusal', stop_details=None, content=[])
        client = make_client(result=response)
        with pytest.raises(AIBatchRefused):
            client.structured_request('s', 'u', SCHEMA, 'medium')
        assert client.calls_made == 1


class TestResponseHandling:
    def test_refusal_raises_batch_refused_with_category(self):
        response = SimpleNamespace(
            stop_reason='refusal',
            stop_details=SimpleNamespace(category='prompt_injection'),
            content=[],
        )
        client = make_client(result=response)
        with pytest.raises(AIBatchRefused, match='prompt_injection'):
            client.structured_request('s', 'u', SCHEMA, 'medium')

    def test_refusal_without_stop_details_attribute(self):
        response = SimpleNamespace(stop_reason='refusal', content=[])
        client = make_client(result=response)
        with pytest.raises(AIBatchRefused, match='refused'):
            client.structured_request('s', 'u', SCHEMA, 'medium')

    def test_max_tokens_stop_raises(self):
        response = SimpleNamespace(stop_reason='max_tokens', stop_details=None, content=[])
        client = make_client(result=response)
        with pytest.raises(AIAnalysisError, match='response truncated'):
            client.structured_request('s', 'u', SCHEMA, 'medium')

    def test_first_text_block_is_parsed(self):
        response = SimpleNamespace(
            stop_reason='end_turn',
            stop_details=None,
            content=[
                SimpleNamespace(type='thinking', thinking='...'),
                SimpleNamespace(type='text', text=json.dumps({'verdicts': []})),
            ],
        )
        client = make_client(result=response)
        assert client.structured_request('s', 'u', SCHEMA, 'low') == {'verdicts': []}

    def test_no_text_block_raises(self):
        response = SimpleNamespace(stop_reason='end_turn', stop_details=None, content=[])
        client = make_client(result=response)
        with pytest.raises(AIAnalysisError, match='no text content'):
            client.structured_request('s', 'u', SCHEMA, 'low')

    def test_invalid_json_raises(self):
        response = SimpleNamespace(
            stop_reason='end_turn',
            stop_details=None,
            content=[SimpleNamespace(type='text', text='not json {')],
        )
        client = make_client(result=response)
        with pytest.raises(AIAnalysisError, match='not valid JSON'):
            client.structured_request('s', 'u', SCHEMA, 'low')

    def test_non_object_json_raises(self):
        response = SimpleNamespace(
            stop_reason='end_turn',
            stop_details=None,
            content=[SimpleNamespace(type='text', text='[1, 2]')],
        )
        client = make_client(result=response)
        with pytest.raises(AIAnalysisError, match='not a JSON object'):
            client.structured_request('s', 'u', SCHEMA, 'low')


class TestRequestShape:
    def test_api_contract_kwargs(self):
        # The API-contract guard: exactly these kwargs, exactly this shape.
        client = make_client(result=text_response({'findings': []}), model='claude-opus-5-5')
        schema = {
            'type': 'object',
            'properties': {'x': {'type': 'string'}},
            'required': ['x'],
            'additionalProperties': False,
        }
        client.structured_request('system text', 'user text', schema, 'high')
        kwargs = client._client.kwargs
        assert kwargs['model'] == 'claude-opus-5-5'
        assert kwargs['max_tokens'] == 16000
        assert kwargs['system'] == 'system text'
        assert kwargs['messages'] == [{'role': 'user', 'content': 'user text'}]
        assert kwargs['output_config']['format']['type'] == 'json_schema'
        assert kwargs['output_config']['format']['schema'] is schema
        assert kwargs['output_config']['effort'] == 'high'
        # Nothing else is sent; in particular no api_key kwarg (the SDK must
        # resolve ANTHROPIC_API_KEY itself).
        assert set(kwargs) == {'model', 'max_tokens', 'system', 'messages', 'output_config'}


class TestExceptionMapping:
    @pytest.mark.parametrize('error_name,expected,expected_cls', [
        ('AuthenticationError', 'set ANTHROPIC_API_KEY', AIAuthenticationFailed),
        ('RateLimitError', 'rate limited', AIAnalysisError),
        ('APIConnectionError', 'Could not reach the Anthropic API', AIAnalysisError),
    ])
    def test_sdk_errors_mapped_to_constructed_messages(self, monkeypatch, error_name, expected, expected_cls):
        sdk = dummy_sdk()
        monkeypatch.setattr(ai_client, 'anthropic', sdk)
        secret = 'sk-ant-' + 'a' * 30
        error = getattr(sdk, error_name)(f'raw body quoting {secret}')
        client = make_client(result=error)
        with pytest.raises(AIAnalysisError) as excinfo:
            client.structured_request('s', 'u', SCHEMA, 'medium')
        assert isinstance(excinfo.value, expected_cls)
        assert expected in str(excinfo.value)
        # The raised message is constructed, never raw str(e).
        assert secret not in str(excinfo.value)
        assert 'raw body' not in str(excinfo.value)
        if expected_cls is AIAnalysisError:
            # Only auth failures may carry the stop-the-scan subclass.
            assert not isinstance(excinfo.value, (AIAuthenticationFailed, AIBudgetExhausted))

    def test_status_error_includes_http_code_only(self, monkeypatch):
        sdk = dummy_sdk()
        monkeypatch.setattr(ai_client, 'anthropic', sdk)
        client = make_client(result=sdk.APIStatusError(529))
        with pytest.raises(AIAnalysisError, match=r'Anthropic API error \(HTTP 529\)') as excinfo:
            client.structured_request('s', 'u', SCHEMA, 'medium')
        assert 'secret body' not in str(excinfo.value)

    def test_missing_credentials_typeerror_mapped(self, monkeypatch):
        # anthropic 2.x raises a plain TypeError at request time when no
        # credentials can be resolved (the client constructs without a key).
        sdk = dummy_sdk()
        monkeypatch.setattr(ai_client, 'anthropic', sdk)
        error = TypeError('"Could not resolve authentication method. Expected one of api_key..."')
        client = make_client(result=error)
        with pytest.raises(AIAuthenticationFailed, match='set ANTHROPIC_API_KEY'):
            client.structured_request('s', 'u', SCHEMA, 'medium')

    def test_unrelated_typeerror_propagates(self, monkeypatch):
        sdk = dummy_sdk()
        monkeypatch.setattr(ai_client, 'anthropic', sdk)
        client = make_client(result=TypeError('unexpected keyword argument'))
        with pytest.raises(TypeError, match='unexpected keyword argument'):
            client.structured_request('s', 'u', SCHEMA, 'medium')
