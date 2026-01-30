import sqlite3
from pysqlcipher3 import dbapi2 as sqlite
import getpass

def manage_folders(db_name, password):
    try:
        conn = sqlite.connect(db_name)
        cursor = conn.cursor()
        cursor.execute(f"PRAGMA key = '{password}'")

        while True:
            print("\n--- Folder Management ---")
            print("1. List all folders")
            print("2. Rename a folder")
            print("3. Create new folder")
            print("4. Exit")
            
            choice = input("Select an option: ")

            if choice == '1':
                cursor.execute("SELECT id, name FROM folders")
                for row in cursor.fetchall():
                    print(f"ID: {row[0]} | Name: {row[1]}")
            
            elif choice == '2':
                f_id = input("Enter Folder ID to rename: ")
                new_name = input("Enter new name: ")
                cursor.execute("UPDATE folders SET name = ? WHERE id = ?", (new_name, f_id))
                conn.commit()
                print("Updated!")

            elif choice == '3':
                new_name = input("New folder name: ")
                cursor.execute("INSERT INTO folders (name) VALUES (?)", (new_name,))
                conn.commit()
                print("Created!")

            elif choice == '4':
                break

    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    pw = getpass.getpass("Enter Database Key: ")
    manage_folders("passwords.db", pw)
