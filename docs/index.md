# LLM Guard

The Security Toolkit for LLM Interactions.

**Actively maintained** community fork. Upstream was archived; development continues here under the MIT license.

[**Changelog**](./changelog.md) | [**GitHub**](https://github.com/UnoDomination/llm-guard) | [**Issues**](https://github.com/UnoDomination/llm-guard/issues)

## What is LLM Guard?

![LLM-Guard](./assets/flow.png)

LLM Guard sanitizes prompts and model outputs so LLM apps stay safer in production. It helps with prompt injection resistance, PII and secrets leakage prevention, toxicity and policy filtering, and output checks (JSON, URLs, refusals, relevance, and more).

## Installation

Install from this repository:

```sh
pip install git+https://github.com/UnoDomination/llm-guard.git
```

Requires Python 3.9+. See [Installation](./get_started/installation.md) for more options.

## Getting started

- [ChatGPT + LLM Guard](https://github.com/UnoDomination/llm-guard/blob/main/examples/openai_api.py)
- [Installation](./get_started/installation.md)

## Community and contributing

- Star the [repo](https://github.com/UnoDomination/llm-guard) if this is useful
- Open an [issue](https://github.com/UnoDomination/llm-guard/issues)
- Read [CONTRIBUTING.md](https://github.com/UnoDomination/llm-guard/blob/main/CONTRIBUTING.md) before opening a PR

## Credits

Originally created by [Protect AI](https://github.com/protectai/llm-guard) (MIT). This fork is independently maintained and is not affiliated with Protect AI or Palo Alto Networks.
