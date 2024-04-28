install:
    poetry install

run:
    poetry run uvicorn auth0-fastapi-sample.main:app --reload

test:
    poetry run pytest -rx -vv tests/unit

integrations:
    poetry run pytest -rx -vv tests/integrations
