# Procfile - Works with Railway, Render, Heroku, Fly.io
web: gunicorn tradeflow.wsgi:application --bind 0.0.0.0:$PORT
release: python manage.py migrate
