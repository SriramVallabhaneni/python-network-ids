import sqlite3
import logging
import json
import os
from datetime import datetime, timezone

# ─── Paths ────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE_DIR, "logs", "alerts.log")
DB_FILE  = os.path.join(BASE_DIR, "data", "alerts.db")

# ─── Logger setup ─────────────────────────────────────────
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.WARNING,
    format="%(asctime)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# ─── How long before same attack+IP can alert again ───────
DB_COOLDOWN = 120      # 2 minutes — longer than a typical nmap scan

# ─── Database setup ───────────────────────────────────────
def init_db():
    """Create alerts and dedup tables if they don't exist."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            attack_type TEXT    NOT NULL,
            source_ip   TEXT    NOT NULL,
            details     TEXT    NOT NULL
        )
    """)

    # ← NEW: dedup table tracks last alert per attack+IP
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts_dedup (
            attack_type TEXT    NOT NULL,
            source_ip   TEXT    NOT NULL,
            last_alerted TEXT   NOT NULL,
            PRIMARY KEY (attack_type, source_ip)
        )
    """)

    conn.commit()
    conn.close()

# ─── Dedup check ──────────────────────────────────────────
def _is_duplicate(cursor, attack_type, source_ip, now):
    """
    Returns True if this attack+IP was already alerted
    within the DB_COOLDOWN window.
    """
    cursor.execute("""
        SELECT last_alerted FROM alerts_dedup
        WHERE attack_type = ? AND source_ip = ?
    """, (attack_type, source_ip))
    row = cursor.fetchone()

    if row is None:
        return False

    last_alerted = datetime.fromisoformat(row[0])
    diff = (now - last_alerted).total_seconds()
    return diff < DB_COOLDOWN

def _update_dedup(cursor, attack_type, source_ip, now):
    """Upsert the last alert time for this attack+IP."""
    cursor.execute("""
        INSERT INTO alerts_dedup (attack_type, source_ip, last_alerted)
        VALUES (?, ?, ?)
        ON CONFLICT(attack_type, source_ip)
        DO UPDATE SET last_alerted = excluded.last_alerted
    """, (attack_type, source_ip, now.isoformat()))

# ─── Core alert function ──────────────────────────────────
def trigger_alert(alert: dict):
    """
    Receives an alert dict from the detector and:
    1. Adds a timestamp
    2. Checks dedup table — skips if duplicate
    3. Prints to terminal
    4. Writes to log file
    5. Stores in SQLite
    """
    now = datetime.now(timezone.utc)
    alert["timestamp"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # ← NEW: check dedup before doing anything
        if _is_duplicate(cursor, alert["attack_type"], alert["source_ip"], now):
            conn.close()
            return                  # silent skip — not a new alert

        # Not a duplicate — update dedup table
        _update_dedup(cursor, alert["attack_type"], alert["source_ip"], now)

        # Print to terminal
        print(
            f"[!] {alert['timestamp']} | "
            f"{alert['attack_type']} | "
            f"{alert['source_ip']} | "
            f"{alert['details']}"
        )

        # Log file
        logger.warning(json.dumps(alert))

        # Insert into alerts table
        cursor.execute("""
            INSERT INTO alerts (timestamp, attack_type, source_ip, details)
            VALUES (?, ?, ?, ?)
        """, (
            alert["timestamp"],
            alert["attack_type"],
            alert["source_ip"],
            alert["details"]
        ))

        conn.commit()

    except sqlite3.Error as e:
        print(f"[DB ERROR] {e}")
    finally:
        conn.close()

# ─── Query helpers ────────────────────────────────────────
def get_recent_alerts(limit=20):
    """Fetch the most recent unique alerts from the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, attack_type, source_ip, details
        FROM alerts
        GROUP BY attack_type, source_ip
        ORDER BY MAX(id) DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_alert_counts():
    """Get total count per attack type."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT attack_type, COUNT(*) as count
        FROM alerts
        GROUP BY attack_type
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows