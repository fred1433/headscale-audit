from __future__ import annotations

import copy
import pathlib

import pytest

from headscale_audit.loaders import from_directory
from headscale_audit.model import Inventory

LAB = pathlib.Path(__file__).resolve().parent.parent / "lab"


def load(name: str) -> Inventory:
    return from_directory(str(LAB / name))


@pytest.fixture(scope="session")
def hardened() -> Inventory:
    return load("hardened")


@pytest.fixture(scope="session")
def insecure() -> Inventory:
    return load("insecure")


@pytest.fixture()
def base(hardened: Inventory) -> Inventory:
    """A deployment where every control passes, ready to be mutated."""
    return copy.deepcopy(hardened)
