VENV = myenv
PIP = $(VENV)/bin/pip
PYTHON = $(VENV)/bin/python

install:
	$(PIP) install fastapi uvicorn requests
	$(PIP) install .
	$(PIP) install pytest "httpx<0.28.0"

test:
	$(PYTHON) -m pytest tests/

run:
	uvicorn processing_pipeline.api:app --reload --host 0.0.0.0 --port 8000

docker-build:
	docker build -f deployment/Dockerfile -t processing_pipeline .

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf build/ dist/ *.egg-info/
