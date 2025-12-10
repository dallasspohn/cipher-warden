#!/usr/bin/env python3
"""
Bitwarden JSON to SQLCipher Database Importer
Converts Bitwarden export to encrypted local database
"""

import json
import sqlite3
import sys
import getpass
from pathlib import Path
from datetime import datetime

# Try to import pysqlcipher3, fallback to regular sqlite with warning
try:
    from pysqlcipher3 import dbapi2 as sqlcipher
    USE_SQLCIPHER = True
except ImportError:
    print("WARNING: pysqlcipher3 not installed. Using unencrypted SQLite.")
    print("Install with: pip install pysqlcipher3")
    USE_SQLCIPHER = False
    sqlcipher = sqlite3


def create_database(db_path, password=None):
    """Create encrypted database with schema"""
    if USE_SQLCIPHER:
        conn = sqlcipher.connect(db_path)
        conn.execute(f"PRAGMA key = '{password}'")
        conn.execute("PRAGMA cipher_compatibility = 4")
    else:
        conn = sqlite3.connect(db_path)

    cursor = conn.cursor()

    # Folders table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS folders (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Items table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id TEXT PRIMARY KEY,
            folder_id TEXT,
            name TEXT NOT NULL,
            username TEXT,
            password TEXT,
            notes TEXT,
            favorite INTEGER DEFAULT 0,
            reprompt INTEGER DEFAULT 0,
            type INTEGER DEFAULT 1,
            created_date TEXT,
            revision_date TEXT,
            FOREIGN KEY (folder_id) REFERENCES folders(id)
        )
    """)

    # URIs table (one item can have multiple URIs)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS uris (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id TEXT NOT NULL,
            uri TEXT NOT NULL,
            FOREIGN KEY (item_id) REFERENCES items(id)
        )
    """)

    # Fields table (custom fields)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS fields (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id TEXT NOT NULL,
            name TEXT,
            value TEXT,
            type INTEGER,
            FOREIGN KEY (item_id) REFERENCES items(id)
        )
    """)

    # Create indexes for faster searches
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_items_folder ON items(folder_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_items_name ON items(name)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_uris_item ON uris(item_id)")

    conn.commit()
    return conn


def import_data(conn, json_file):
    """Import Bitwarden JSON data into database"""
    with open(json_file, 'r') as f:
        data = json.load(f)

    cursor = conn.cursor()

    # Import folders
    folders = data.get('folders', [])
    print(f"Importing {len(folders)} folders...")
    for folder in folders:
        cursor.execute("""
            INSERT OR REPLACE INTO folders (id, name)
            VALUES (?, ?)
        """, (folder['id'], folder['name']))

    # Import items
    items = data.get('items', [])
    print(f"Importing {len(items)} items...")

    for item in items:
        login = item.get('login', {})

        cursor.execute("""
            INSERT OR REPLACE INTO items
            (id, folder_id, name, username, password, notes, favorite, reprompt, type, created_date, revision_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            item['id'],
            item.get('folderId'),
            item['name'],
            login.get('username', ''),
            login.get('password', ''),
            item.get('notes', ''),
            item.get('favorite', 0),
            item.get('reprompt', 0),
            item.get('type', 1),
            item.get('creationDate'),
            item.get('revisionDate')
        ))

        # Import URIs
        uris = login.get('uris', [])
        for uri_obj in uris:
            if uri_obj.get('uri'):
                cursor.execute("""
                    INSERT INTO uris (item_id, uri)
                    VALUES (?, ?)
                """, (item['id'], uri_obj['uri']))

        # Import custom fields
        fields = item.get('fields', [])
        for field in fields:
            cursor.execute("""
                INSERT INTO fields (item_id, name, value, type)
                VALUES (?, ?, ?, ?)
            """, (
                item['id'],
                field.get('name'),
                field.get('value'),
                field.get('type')
            ))

    conn.commit()
    print("Import completed successfully!")

    # Print summary
    cursor.execute("SELECT COUNT(*) FROM folders")
    folder_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM items")
    item_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM uris")
    uri_count = cursor.fetchone()[0]

    print(f"\nSummary:")
    print(f"  Folders: {folder_count}")
    print(f"  Items: {item_count}")
    print(f"  URIs: {uri_count}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python import_bitwarden.py <bitwarden_export.json>")
        print("\nThis will create an encrypted 'passwords.db' file")
        sys.exit(1)

    json_file = sys.argv[1]

    if not Path(json_file).exists():
        print(f"Error: File '{json_file}' not found")
        sys.exit(1)

    db_path = "passwords.db"

    # Get master password
    if USE_SQLCIPHER:
        print("=" * 50)
        print("Set your MASTER PASSWORD")
        print("Remember this - you'll need it to access your passwords!")
        print("=" * 50)
        password = getpass.getpass("Master password: ")
        password_confirm = getpass.getpass("Confirm password: ")

        if password != password_confirm:
            print("Error: Passwords don't match")
            sys.exit(1)

        if len(password) < 8:
            print("Warning: Password is short. Consider using 12+ characters")
    else:
        password = None
        print("\nWARNING: Database will NOT be encrypted!")
        print("Install pysqlcipher3 for encryption: pip install pysqlcipher3\n")

    # Create database and import
    print(f"\nCreating database: {db_path}")
    conn = create_database(db_path, password)

    print(f"Importing from: {json_file}")
    import_data(conn, json_file)

    conn.close()

    print(f"\n✓ Database created: {db_path}")
    if USE_SQLCIPHER:
        print("✓ Database is encrypted with your master password")
    print("\nNext step: Run the Flask app to access your passwords")


if __name__ == "__main__":
    main()
