# Installing LLM Guard

## Prerequisites

Supported Python versions:

- 3.9
- 3.10
- 3.11

## Using `pip`

!!! note

    Consider installing the LLM Guard python packages on a virtual environment like `venv` or `conda`.

Install from this repository (recommended):

```bash
pip install git+https://github.com/UnoDomination/llm-guard.git
```

> The PyPI name `llm-guard` still points at the last upstream release. Prefer installing from this repo.

If you have issues installing due to missing `torch`, try:

```bash
pip install wheel
pip install torch==2.0.1
pip install "git+https://github.com/UnoDomination/llm-guard.git" --no-build-isolation
```

## Install from source

Clone the repo:

- Using HTTPS
```bash
git clone https://github.com/UnoDomination/llm-guard.git
```
- Using SSH
```bash
git clone git@github.com:UnoDomination/llm-guard.git
```

We recommend to use a virtual environment like `venv` or `conda` to install the package.

```bash
python -m venv venv
source venv/bin/activate
```

Then, install the package using `pip`:

```bash
python -m pip install ".[dev]"
```
