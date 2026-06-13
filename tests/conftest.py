import pytest
from rich.console import Console


@pytest.fixture
def console():
    return Console()