import sys
from pysqlcipher3 import dbapi2 as sqlite

def list_tables(db_name, password):
    try:
        # Connect to the database
        conn = sqlite.connect(db_name)
        cursor = conn.cursor()

        # Provide the key to unlock the database
        cursor.execute(f"PRAGMA key = '{password}'")

        # Query the sqlite_master table for all user-defined tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        
        tables = cursor.fetchall()

        if tables:
            print(f"\nTables in '{db_name}':")
            print("-" * 30)
            for table in tables:
                print(f" -> {table[0]}")
            print("-" * 30)
        else:
            print("No tables found (the database might be empty).")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    # You can change these values or accept them as arguments
    db_file = input("Enter database filename: ")
    db_pass = input("Enter database password: ")
    
    list_tables(db_file, db_pass)
