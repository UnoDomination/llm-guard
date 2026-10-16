# LLM Guard

The Security Toolkit for LLM Interactions.

**Actively maintained** community fork of the original Protect AI project. Upstream was archived; development continues here under the MIT license.

[**Documentation**](./docs/index.md) | [**Changelog**](./docs/changelog.md) | [**Issues**](https://github.com/UnoDomination/llm-guard/issues)

[![GitHub stars](https://img.shields.io/github/stars/UnoDomination/llm-guard.svg?style=social&label=Star)](https://github.com/UnoDomination/llm-guard/stargazers)
[![MIT license](https://img.shields.io/badge/license-MIT-brightgreen.svg)](http://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## What is LLM Guard?

LLM Guard sanitizes prompts and model outputs so LLM apps stay safer in production. It helps with:

- Prompt injection resistance
- PII and secrets leakage prevention
- Toxicity and policy filtering
- Output checks (JSON, URLs, refusals, relevance, and more)

## Installation

Install from this repository:

```sh
pip install git+https://github.com/UnoDomination/llm-guard.git
```

> The PyPI package name `llm-guard` still serves the last upstream release (`0.3.16`). Prefer installing from this repo until a community package is published.

Requires **Python 3.9+**. If install fails, try upgrading pip:

```sh
python -m pip install --upgrade pip
```

## Getting started

**Examples:**

- [ChatGPT + LLM Guard](./examples/openai_api.py)
- [API deployment](./docs/api/overview.md)

## Supported scanners

### Prompt scanners

- [Anonymize](./docs/input_scanners/anonymize.md)
- [BanCode](./docs/input_scanners/ban_code.md)
- [BanCompetitors](./docs/input_scanners/ban_competitors.md)
- [BanSubstrings](./docs/input_scanners/ban_substrings.md)
- [BanTopics](./docs/input_scanners/ban_topics.md)
- [Code](./docs/input_scanners/code.md)
- [Gibberish](./docs/input_scanners/gibberish.md)
- [InvisibleText](./docs/input_scanners/invisible_text.md)
- [Language](./docs/input_scanners/language.md)
- [PromptInjection](./docs/input_scanners/prompt_injection.md)
- [Regex](./docs/input_scanners/regex.md)
- [Secrets](./docs/input_scanners/secrets.md)
- [Sentiment](./docs/input_scanners/sentiment.md)
- [TokenLimit](./docs/input_scanners/token_limit.md)
- [Toxicity](./docs/input_scanners/toxicity.md)

### Output scanners

- [BanCode](./docs/output_scanners/ban_code.md)
- [BanCompetitors](./docs/output_scanners/ban_competitors.md)
- [BanSubstrings](./docs/output_scanners/ban_substrings.md)
- [BanTopics](./docs/output_scanners/ban_topics.md)
- [Bias](./docs/output_scanners/bias.md)
- [Code](./docs/output_scanners/code.md)
- [Deanonymize](./docs/output_scanners/deanonymize.md)
- [JSON](./docs/output_scanners/json.md)
- [Language](./docs/output_scanners/language.md)
- [LanguageSame](./docs/output_scanners/language_same.md)
- [MaliciousURLs](./docs/output_scanners/malicious_urls.md)
- [NoRefusal](./docs/output_scanners/no_refusal.md)
- [ReadingTime](./docs/output_scanners/reading_time.md)
- [FactualConsistency](./docs/output_scanners/factual_consistency.md)
- [Gibberish](./docs/output_scanners/gibberish.md)
- [Regex](./docs/output_scanners/regex.md)
- [Relevance](./docs/output_scanners/relevance.md)
- [Sensitive](./docs/output_scanners/sensitive.md)
- [Sentiment](./docs/output_scanners/sentiment.md)
- [Toxicity](./docs/output_scanners/toxicity.md)
- [URLReachability](./docs/output_scanners/url_reachability.md)

## Community and contributing

Contributions are welcome: bug reports, features, docs, and PRs.

- Star the repo if this is useful
- Open an [issue](https://github.com/UnoDomination/llm-guard/issues)
- Read [CONTRIBUTING.md](./CONTRIBUTING.md) before opening a PR
- Browse [docs](./docs/index.md)

## Credits

Originally created by [Protect AI](https://github.com/protectai/llm-guard) (MIT). This fork is independently maintained and is not affiliated with Protect AI or Palo Alto Networks.
