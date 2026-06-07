"""Application entrypoint (backward-compatible module name)."""

from factory import bootstrap_schema, create_app

app = create_app()


if __name__ == "__main__":
    bootstrap_schema()
    app.run(debug=True)
