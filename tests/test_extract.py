from slopwatch.extract import extract, normalize_pypi


def names(found, kind=None):
    return {n for _, n, k in found if kind is None or k == kind}


def test_pip_install_basic_and_flags():
    text = "Run:\n```bash\npip install -U requests==2.31 'pandas[excel]>=2' -r requirements.txt\n```"
    assert names(extract(text, "pypi"), "install") == {"requests", "pandas"}


def test_pip_variants_and_normalization():
    text = "python -m pip install Flask_Login\nuv add pydantic-settings\npoetry add ruamel.yaml"
    assert names(extract(text, "pypi"), "install") == {"flask-login", "pydantic-settings", "ruamel-yaml"}


def test_pip_ignores_prose_and_paths():
    text = "You can pip install the package, or pip install ./local_pkg or pip install git+https://x/y.git"
    assert names(extract(text, "pypi"), "install") == set()


def test_install_in_prose_is_ignored_but_inline_code_counts():
    text = "First pip install needed packages, then npm install side.\nOr run `pip install fitparse` here."
    assert names(extract(text, "pypi"), "install") == {"fitparse"}


def test_shell_prompt_lines_count():
    assert names(extract("$ npm install express", "npm"), "install") == {"express"}


def test_python_imports_skip_stdlib_and_relative():
    code = "```python\nimport os, sys\nimport numpy as np\nfrom fitparse import FitFile\nfrom . import utils\nimport hl7.client\n```"
    assert names(extract(code, "pypi"), "import") == {"numpy", "fitparse", "hl7"}


def test_npm_install_scoped_and_versions():
    text = "```\nnpm i -D @types/node@20 express@^4.18 zod\nyarn add @simplewebauthn/server\n```"
    assert names(extract(text, "npm"), "install") == {"@types/node", "express", "zod", "@simplewebauthn/server"}


def test_js_imports_skip_builtins_and_relative():
    code = (
        "```js\nconst fs = require('fs');\nconst x = require('node:path');\n"
        "import express from 'express';\nimport { a } from './local';\n"
        "import { Client } from '@modelcontextprotocol/sdk/client/index.js';\n```"
    )
    assert names(extract(code, "npm"), "import") == {"express", "@modelcontextprotocol/sdk"}


def test_normalize():
    assert normalize_pypi("Python_Dateutil") == "python-dateutil"


def test_comment_noise_ignored():
    code = "```python\n# No pip install needed – the script uses only the standard library.\n# Pip install requirement\n# pip install requests\n```"
    assert names(extract(code, "pypi"), "install") == {"requests"}
