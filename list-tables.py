import sqlite3
from pysqlcipher3 import dbapi2 as sqlite
import getpass

def inspect_table(db_name, password, table_name):
    try:
        conn = sqlite.connect(db_name)
        cursor = conn.cursor()
        cursor.execute(f"PRAGMA key = '{password}'")

        # 1. Get the Column Names (Schema)
        print(f"\n--- Structure of '{table_name}' ---")
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = cursor.fetchall()
        # Columns: (id, name, type, notnull, default_value, pk)
        for col in columns:
            print(f"Column: {col[1]:<15} | Type: {col[2]}")

        # 2. Get the actual Data (Rows)
        print(f"\n--- Data in '{table_name}' (First 5 rows) ---")
        cursor.execute(f"SELECT * FROM {table_name} LIMIT 5")
        rows = cursor.fetchall()
        
        if rows:
            for row in rows:
                print(row)
        else:
            print("Table is empty.")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    db = "passwords.db"
    pw = getpass.getpass("Enter Key: ")
    target = input("Which table to inspect? (e.g., folders, items): ")
    inspect_table(db, pw, target)
