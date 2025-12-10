# cipher-warden
Cipher-warden is a secure replacement for your exported Bitwarden .json file.

It is meant to be installed on a android phone in a termux terminal.
But you can install it anywhere.
It offers up a simple web interface to access your passwords locally on your network.
## Why?
Bitwarden's official app does not support local storage.
If you want to keep your passwords local, you need an alternative.
Cipher-warden allows you to import your Bitwarden vault and access it securely on your local network

*  ✓ Works perfectly in Termux (no compilation issues).
*  ✓ Encrypts the entire database file.
*  ✓ Same master password approach.
*  ✓ Just as secure for your use case.

# Correct Termux packages
`pkg install python sqlite openssl sqlcipher`

# Then install Python package
`pip install pysqlcipher3`

Export your current Bitwarden vault as a json file.
Run:
`python import_bitwarden.py bitwarden_export_834582**.json`

## When you run it:

* It will ask you to set a master password
* Confirm the password
* It will import all folders, items, URIs, etc.
* Creates passwords.db (encrypted)



then run your flask program.

`python password-manager.py`

What You'll See:
The app will display your phone's local IP information. Then:
From your phone browser:

Go to http://127.0.0.1:5000

From any device on your local network (laptop, tablet, etc):

First, find your phone's IP: ifconfig wlan0 | grep inet
Go to http://192.168.x.xxx:5000 (use your phone's IP)

# Features:
* ✅ Master password login (same one you set during import)
* ✅ Folder navigation with item counts
* ✅ Search across all passwords
* ✅ Click to copy username/password
* ✅ Hover to reveal passwords (blurred by default)
* ✅ 30-minute session timeout for security
* ✅ Works on all devices on your local network

