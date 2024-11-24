#!/bin/bash
IP="127.0.0.1"

uwsgi --plugin python3 --http-socket $IP:5000 --wsgi-file uWSGI.py --callable app --processes 6 --threads 8 --stats $IP:9191 --logto hot_wallet.log

