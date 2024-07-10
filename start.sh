#!/bin/sh

# Export the FLASK_APP environment variable
export FLASK_APP=app.py  # Cambia `app.py` por el nombre de tu archivo principal de Flask

# Iniciar el servidor Flask
flask run --host=0.0.0.0 --port=8080
