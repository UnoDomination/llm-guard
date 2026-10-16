> [!NOTE]
> **Open source · actively maintained here.** Upstream [protectai/llm-guard](https://github.com/protectai/llm-guard) was archived. This community fork continues development under the MIT license.

# LLM Guard - The Security Toolkit for LLM Interactions

LLM Guard is a comprehensive tool designed to fortify the security of Large Language Models (LLMs).

[**Documentation**](./docs/index.md) | [**Changelog**](./docs/changelog.md) | [**Issues**](https://github.com/UnoDomination/llm-guard/issues)

[![GitHub
stars](https://img.shields.io/github/stars/UnoDomination/llm-guard.svg?style=social&label=Star&maxAge=2592000)](https://github.com/UnoDomination/llm-guard/stargazers/)
[![MIT license](https://img.shields.io/badge/license-MIT-brightgreen.svg)](http://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

## What is LLM Guard?

![LLM-Guard](docs/assets/flow.png)

By offering sanitization, detection of harmful language, prevention of data leakage, and resistance against prompt
injection attacks, LLM-Guard ensures that your interactions with LLMs remain safe and secure.

## Installation

Install from this repository:

```sh
pip install git+https://github.com/UnoDomination/llm-guard.git
```

> The PyPI package name `llm-guard` still points at the last upstream release (`0.3.16`). Prefer installing from this repo until a community package is published.

## Getting Started

**Important Notes**:

- LLM Guard is designed for easy integration and deployment in production environments.
- Base functionality requires a limited number of libraries. As you explore more advanced features, necessary libraries will be automatically installed.
- Ensure you're using Python version 3.9 or higher. Confirm with: `python --version`.
- Library installation issues? Consider upgrading pip: `python -m pip install --upgrade pip`.

**Examples**:

- Get started with [ChatGPT and LLM Guard](./examples/openai_api.py).
- Deploy LLM Guard as [API](./docs/api/overview.md)

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

## Community, Contributing, Docs & Support

LLM Guard is an open source solution.
We are committed to a transparent development process and highly appreciate any contributions.

**Contact:** there is no public email. [Open a GitHub Issue](https://github.com/UnoDomination/llm-guard/issues/new) and the maintainer will be notified. For security reports, see [SECURITY.md](./SECURITY.md).

- Star the repo if this is useful
- Read the [docs](./docs/index.md)
- [Open an issue](https://github.com/UnoDomination/llm-guard/issues) for bugs, questions, or feature ideas
- See [CONTRIBUTING.md](./CONTRIBUTING.md) before opening a PR

## Credits

Originally created by [Protect AI](https://github.com/protectai/llm-guard) (MIT). This fork is independently maintained and is not affiliated with Protect AI or Palo Alto Networks.
