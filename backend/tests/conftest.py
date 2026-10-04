"""Keep automatic output from all application tests away from real reports."""
import pytest


@pytest.fixture(autouse=True)
def isolated_default_results(tmp_path, monkeypatch):
    monkeypatch.setattr('app.main.DEFAULT_RESULTS_ROOT', tmp_path / 'generated-results')
