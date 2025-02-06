#!/bin/bash

# Tworzenie środowiska wirtualnego
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Tworzenie pliku usługi
SERVICE_FILE=/etc/systemd/system/monitor.service

echo "[Unit]
Description=Monitor System Service
After=network.target

[Service]
ExecStart=$(pwd)/venv/bin/python $(pwd)/app.py
WorkingDirectory=$(pwd)
Restart=always
User=$(whoami)
Group=$(whoami)
Environment=\"PYTHONUNBUFFERED=1\"

[Install]
WantedBy=multi-user.target
" | tee $SERVICE_FILE

systemctl daemon-reload
systemctl enable monitor
systemctl start monitor

echo "Monitor System Service is installed and running."
