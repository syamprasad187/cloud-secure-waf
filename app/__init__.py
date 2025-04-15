from flask import Flask # type: ignore

app = Flask(__name__)
app.config.from_object('config.Config')

from app import routes