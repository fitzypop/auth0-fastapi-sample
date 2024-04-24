# Auth0 + Python + FastAPI API Seed

Forked from [Auth0 Blog | FastAPI Example](https://github.com/auth0-blog/auth0-python-fastapi-sample)

I've updated this repo to the latest versions of all the packages, moved from pip to poetry, and add some test files and mocking examples.

## Dev Requirements

- Python 3.12
  - Pyenv or asdf recommended
- Poetry
- just

### Configuration

The configuration you'll need is mostly information from Auth0, you'll need both the tentant domain and the API information.

This app reads its configuration information from a `.env` file by default.

To create a `.env` file you can copy the `.env.example` file and fill the values accordingly:

```console
cp .env.example .env
```

### Spin up the server

```bash
python3 -m venv .venv
just install
just run
```

Try calling [http://localhost:8000/api/public](http://localhost:8000/api/public)

```bash
curl -X 'GET' \
  'http://localhost:8000/api/public' \
  -H 'accept: application/json'
```

## API documentation

Access [http://localhost:8000/docs](http://localhost:8000/docs). From there you'll see all endpoints and can test your API

### Testing the API

#### Private endpoint

You can then try to do a GET to [http://localhost:8000/api/private](http://localhost:8000/api/private) which will throw an error if you don't send an access token signed with RS256 with the appropriate issuer and audience in the Authorization header.

```bash
curl -X 'GET' \
  'http://localhost:8000/api/private' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer  <FILL YOUR TOKEN HERE>'
```

#### Private-Scoped endpoint

You can also try to do a GET to [http://localhost:8000/api/private-scoped](http://localhost:8000/api/private-scoped) which will throw an error if you don't send an access token with the scope `read:messages` signed with RS256 with the appropriate issuer and audience in the Authorization header.

```bash
curl -X 'GET' \
  'http://localhost:8000/api/private-scoped' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer  <FILL YOUR TOKEN WITH SCOPES HERE>'
```
