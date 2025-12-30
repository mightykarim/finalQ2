import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import app

def test_health_endpoint():
    client = app.app.test_client()
    response = client.get('/health')
    assert response.status_code == 200
    assert response.json["status"] == "ok"

