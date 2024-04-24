install:
    poetry install

run:
    uvicorn application.main:app --reload
