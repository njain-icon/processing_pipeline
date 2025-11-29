import pytest
from fastapi.testclient import TestClient
from processing_pipeline.api import app

@pytest.fixture
def client():
    return TestClient(app)
