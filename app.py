import os

import click
from flask import Flask
from flask.cli import with_appcontext
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def create_app(test_config=None):
    """Create and configure an instance of the Flask application."""
    app = Flask(__name__, instance_relative_config=True)

    # some deploy systems set the database url in the environ
    db_url = os.environ.get("DATABASE_URL")

    if db_url is None:
        # default to a sqlite database in the instance folder
        db_path = os.path.join(app.instance_path, "flaskr.sqlite")
        db_url = f"sqlite:///{db_path}"
        # ensure the instance folder exists
        os.makedirs(app.instance_path, exist_ok=True)

    app.config.from_mapping(
        # default secret that should be overridden in environ or config
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev"),
        SQLALCHEMY_DATABASE_URI=db_url,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile("config.py", silent=True)
    else:
        # load the test config if passed in
        app.config.update(test_config)

    # initialize Flask-SQLAlchemy and the init-db command
    db.init_app(app)
    app.cli.add_command(init_db_command)

    # apply the blueprints to the app
    
    from auth import views as auth_view

    app.register_blueprint(auth_view.bp)

    @app.route('/')
    def hello():
        return 'Hello, World!'

    return app


def init_db():
    db.drop_all()
    db.create_all()


@click.command("init-db")
@with_appcontext
def init_db_command():
    """Clear existing data and create new tables."""
    init_db()
    click.echo("Initialized the database.")