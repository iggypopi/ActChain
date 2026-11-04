# Copyright (c) 2025 Igor Stepansky
# SPDX-License-Identifier: MIT

"""
Anthropic API client wrapper for ActChain's optional AI analysis.

The ``anthropic`` SDK is an optional dependency (the ``ai`` extra) and is
imported lazily so the rest of ActChain works without it. Every SDK error is
mapped to :class:`AIAnalysisError` with a constructed message: raw exception
text can quote request/response bodies and must never reach the console.
"""

import json
import logging
import re
from typing import Any

from ..constants import AI_MAX_CALLS_PER_SCAN, AI_MODEL_PATTERN
from ..utils.security_utils import SecurityUtils

logger = logging.getLogger('actchain.ai.client')

# The lazily imported ``anthropic`` module. Kept at module level so tests can
# patch ``actchain.ai.client.anthropic`` with a stand-in module.
anthropic = None


class AIAnalysisError(Exception):
    """AI analysis could not run or an API request failed."""


class AIBatchRefused(AIAnalysisError):
    """The safety classifier refused one request (that batch is skipped)."""


class AIBudgetExhausted(AIAnalysisError):
    """The per-scan API call budget is exhausted (no further calls can run)."""


class AIAuthenticationFailed(AIAnalysisError):
    """Authentication with the Anthropic API failed (cannot recover mid-scan)."""


def _import_anthropic() -> Any:
    """
    Import the ``anthropic`` SDK on first use.

    Returns:
        The imported ``anthropic`` module.

    Raises:
        AIAnalysisError: If the optional dependency is not installed.
    """
    global anthropic
    if anthropic is None:
        try:
            import anthropic as anthropic_module
        except ImportError as e:
            raise AIAnalysisError(
                'AI analysis requires the "ai" extra: pip install "actchain[ai]"'
            ) from e
        anthropic = anthropic_module
    return anthropic


class AIClient:
    """Budgeted wrapper around the Anthropic Messages API."""

    def __init__(self, model: str):
        """
        Initialize the client.

        Args:
            model: Anthropic model name, validated against AI_MODEL_PATTERN.

        Raises:
            AIAnalysisError: If the model name is invalid or the ``anthropic``
                package is not installed.
        """
        if not isinstance(model, str) or not re.match(AI_MODEL_PATTERN, model):
            shown = SecurityUtils.strip_control_chars(str(model), keep_newlines=False)[:80]
            raise AIAnalysisError(
                f"Invalid AI model name '{shown}' (expected to match {AI_MODEL_PATTERN})"
            )
        self._model = model
        self._calls_made = 0
        self._client = self._create_client()

    def _create_client(self) -> Any:
        """
        Construct the underlying SDK client.

        The API key is deliberately not passed or pre-checked here: the SDK
        resolves ANTHROPIC_API_KEY itself, keeping key handling in one place.

        Returns:
            An ``anthropic.Anthropic`` instance.

        Raises:
            AIAnalysisError: If the ``anthropic`` package is not installed.
        """
        sdk = _import_anthropic()
        return sdk.Anthropic()

    @property
    def calls_made(self) -> int:
        """Number of API requests attempted by this client (budget counter)."""
        return self._calls_made

    def structured_request(self, system: str, user_content: str, schema: dict, effort: str) -> dict:
        """
        Make one structured-output request and return the parsed JSON object.

        Args:
            system: System prompt.
            user_content: User message content.
            schema: JSON schema the response must conform to.
            effort: Output effort level (for example "medium" or "high").

        Returns:
            The response parsed as a JSON object.

        Raises:
            AIBatchRefused: If the safety classifier refused this request.
            AIBudgetExhausted: If the per-scan call budget is exhausted.
            AIAuthenticationFailed: If API authentication failed.
            AIAnalysisError: If the request failed in any other way or
                produced an unusable response.
        """
        if self._calls_made >= AI_MAX_CALLS_PER_SCAN:
            raise AIBudgetExhausted('AI call budget exhausted')

        sdk = _import_anthropic()
        # The budget counts attempts, so increment before the request.
        self._calls_made += 1
        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=16000,
                system=system,
                messages=[{"role": "user", "content": user_content}],
                output_config={
                    "format": {"type": "json_schema", "schema": schema},
                    "effort": effort,
                },
            )
        except sdk.AuthenticationError as e:
            raise AIAuthenticationFailed('Anthropic API authentication failed - set ANTHROPIC_API_KEY') from e
        except sdk.RateLimitError as e:
            raise AIAnalysisError('Anthropic API rate limited - try again later') from e
        except sdk.APIStatusError as e:
            raise AIAnalysisError(f'Anthropic API error (HTTP {getattr(e, "status_code", "unknown")})') from e
        except sdk.APIConnectionError as e:
            raise AIAnalysisError('Could not reach the Anthropic API') from e
        except TypeError as e:
            # anthropic 2.x constructs a client without credentials and only
            # raises (a plain TypeError) on the first request when it cannot
            # resolve any authentication method.
            if 'authentication' in str(e).lower():
                raise AIAuthenticationFailed('Anthropic API authentication failed - set ANTHROPIC_API_KEY') from e
            raise

        if response.stop_reason == 'refusal':
            message = 'AI request refused by the safety classifier'
            stop_details = getattr(response, 'stop_details', None)
            if stop_details is not None:
                category = getattr(stop_details, 'category', None)
                if category:
                    cleaned = SecurityUtils.strip_control_chars(str(category), keep_newlines=False)
                    message = f'{message} (category: {cleaned[:100]})'
            raise AIBatchRefused(message)
        if response.stop_reason == 'max_tokens':
            raise AIAnalysisError('response truncated')

        text = None
        for block in response.content:
            if getattr(block, 'type', None) == 'text':
                text = block.text
                break
        if text is None:
            raise AIAnalysisError('AI response contained no text content')

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as e:
            # Should not happen with structured outputs, but guard anyway.
            raise AIAnalysisError('AI response was not valid JSON') from e
        if not isinstance(parsed, dict):
            raise AIAnalysisError('AI response was not a JSON object')
        return parsed
