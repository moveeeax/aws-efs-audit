import json
import pathlib

import pytest

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def fixtures_dir() -> pathlib.Path:
    return FIXTURES


@pytest.fixture
def prod() -> dict:
    return load("prod.json")


@pytest.fixture
def clean() -> dict:
    return load("clean.json")
