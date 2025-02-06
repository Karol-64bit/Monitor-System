import sqlite3
import re
import time
import os

db_path = "logs_database.db"
nginx_log_path = "nginx_logs_3"
apache_access_log_path = "apache_access_logs"
apache_error_log_path = "apache_error_logs"
dev_version = True

# Funkcja do parsowania logów Nginx
def parse_nginx_log(line):
    pattern = (
        r'(?P<ip>[\d\.]+) - - \[(?P<date_time>[^\]]+)\] '
        r'"(?P<method>[A-Z]+) (?P<url>.+?) (?P<protocol>HTTP/\d\.\d)" '
        r'(?P<status>\d{3}) (?P<size>\d+|-) '
        r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
    )
    match = re.match(pattern, line)
    if match:
        return match.groupdict()
    return None

# Funkcja do parsowania logów Apache access (z user_agent)
def parse_apache_access_log(line):
    pattern = (
        r'(?P<ip>[\d\.]+) - - \[(?P<date_time>[^\]]+)\] '
        r'"(?P<method>[A-Z]+) (?P<url>.+?) (?P<protocol>HTTP/\d\.\d)" '
        r'(?P<status>\d{3}) (?P<size>\d+|-) '
        r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
    )
    match = re.match(pattern, line)
    if match:
        return match.groupdict()
    return None

# Funkcja do parsowania logów Apache error
def parse_apache_error_log(line):
    # pattern = (
    #     r'\[(?P<date_time>[^\]]+)\] \[(?P<log_level>[^\]]+)\] '
    #     r'\[pid (?P<pid>\d+)\] (?P<message>.+)'
    # )
    pattern = (
        r'\[(?P<date_time>[^\]]+)\] \[(?P<log_level>[^\]]+)\] '  # Data i poziom logu
        r'\[pid (?P<pid>\d+):tid \d+\] \[client (?P<client_ip>[^\]]+)\] '  # PID i klient
        r'(?P<message>.+)'  # Komunikat błędu
    )
    match = re.match(pattern, line)
    print(match)
    if match:
        return match.groupdict()
    return None

# Funkcja do zapisywania danych w bazie SQLite (z user_agent dla apache_access_logs)
def save_to_database(db_path, table_name, data):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    if table_name == "nginx_logs":
        cursor.execute("""
            INSERT INTO nginx_logs (
                ip, date_time, method, url, protocol, status, size, user_agent
            ) VALUES (:ip, :date_time, :method, :url, :protocol, :status, :size, :user_agent)
        """, data)
    elif table_name == "apache_access_logs":
        cursor.execute("""
            INSERT INTO apache_access_logs (
                ip, date_time, method, url, protocol, status, size, user_agent
            ) VALUES (:ip, :date_time, :method, :url, :protocol, :status, :size, :user_agent)
        """, data)
    elif table_name == "apache_error_logs":
        cursor.execute("""
            INSERT INTO apache_error_logs (
                date_time, log_level, pid, message
            ) VALUES (:date_time, :log_level, :pid, :message)
        """, data)

    conn.commit()
    conn.close()

# Główna funkcja do przetwarzania logów
def process_logs(db_path, nginx_log_path, apache_access_log_path, apache_error_log_path):
    if os.path.exists(nginx_log_path):
        with open(nginx_log_path, 'r') as f:
            for line in f:
                parsed = parse_nginx_log(line)
                if parsed:
                    save_to_database(db_path, "nginx_logs", parsed)

    if os.path.exists(apache_access_log_path):
        with open(apache_access_log_path, 'r') as f:
            for line in f:
                parsed = parse_apache_access_log(line)
                if parsed:
                    save_to_database(db_path, "apache_access_logs", parsed)

    if os.path.exists(apache_error_log_path):
        print("test")
        with open(apache_error_log_path, 'r') as f:
            for line in f:
                print(line)
                parsed = parse_apache_error_log(line)
                if parsed:
                    save_to_database(db_path, "apache_error_logs", parsed)

# Funkcja do tworzenia bazy danych i tabel (z user_agent dla apache_access_logs)
def setup_database(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Tabela dla logów Nginx
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS nginx_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            date_time DATETIME,
            method TEXT,
            url TEXT,
            protocol TEXT,
            status INTEGER,
            size INTEGER,
            user_agent TEXT
        )
    """)

    # Tabela dla logów Apache access
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS apache_access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            date_time DATETIME,
            method TEXT,
            url TEXT,
            protocol TEXT,
            status INTEGER,
            size INTEGER,
            user_agent TEXT
        )
    """)

    # Tabela dla logów Apache error
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS apache_error_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date_time DATETIME,
            log_level TEXT,
            pid INTEGER,
            message TEXT
        )
    """)

    conn.commit()
    conn.close()

def run_aggregator():

    # Inicjalizacja bazy danych
    setup_database(db_path)

    # print("Test threat completely")

    if(dev_version):
        process_logs(db_path, nginx_log_path, apache_access_log_path, apache_error_log_path)
    else:
        while True:
            process_logs(db_path, nginx_log_path, apache_access_log_path, apache_error_log_path)
            time.sleep(60)  # Oczekiwanie 60 sekund przed kolejną iteracją


