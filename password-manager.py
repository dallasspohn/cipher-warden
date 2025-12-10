
#!/usr/bin/env python3
"""
Local Password Manager Web Interface
Access your encrypted Bitwarden data via web browser
"""

from flask import Flask, render_template_string, request, session, redirect, url_for, jsonify
from pysqlcipher3 import dbapi2 as sqlcipher
import secrets
import os
import uuid
import string
from datetime import timedelta, datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

DB_PATH = 'passwords.db'

# Session timeout decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'authenticated' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def get_db_connection(password):
    """Connect to encrypted database"""
    try:
        conn = sqlcipher.connect(DB_PATH)
        conn.execute(f"PRAGMA key = '{password}'")
        conn.execute("PRAGMA cipher_compatibility = 4")
        # Test connection by running a simple query
        conn.execute("SELECT COUNT(*) FROM folders")
        conn.row_factory = sqlcipher.Row
        return conn
    except Exception as e:
        return None


def calculate_password_age(revision_date):
    """Calculate password age in days"""
    if not revision_date:
        return None
    try:
        rev_date = datetime.fromisoformat(revision_date.replace('Z', '+00:00'))
        age_days = (datetime.utcnow().replace(tzinfo=rev_date.tzinfo) - rev_date).days
        return age_days
    except:
        return None


def get_age_warning(age_days):
    """Return warning level based on password age"""
    if age_days is None:
        return None
    if age_days > 365:
        return 'critical'  # Red - over 1 year
    elif age_days > 180:
        return 'warning'   # Yellow - over 6 months
    return None


# HTML Templates
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Password Manager - Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .login-box {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 400px;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 500;
        }
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            width: 100%;
            padding: 14px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.3s;
        }
        button:hover {
            background: #5568d3;
        }
        .error {
            background: #fee;
            color: #c33;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 20px;
            border-left: 4px solid #c33;
        }
        .lock-icon {
            text-align: center;
            font-size: 48px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <div class="lock-icon">🔒</div>
        <h1>Password Manager</h1>
        <p class="subtitle">Enter your master password</p>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST">
            <div class="form-group">
                <label for="password">Master Password</label>
                <input type="password" id="password" name="password" autofocus required>
            </div>
            <button type="submit">Unlock</button>
        </form>
    </div>
</body>
</html>
"""

MAIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Password Manager</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            background: #f5f5f5;
        }
        .header {
            background: white;
            padding: 15px 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        .header h1 {
            font-size: 20px;
            color: #333;
        }
        .header-actions {
            display: flex;
            gap: 10px;
        }
        .btn {
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            text-decoration: none;
            font-size: 14px;
            font-weight: 500;
        }
        .btn-primary {
            background: #28a745;
            color: white;
        }
        .btn-primary:hover {
            background: #218838;
        }
        .btn-danger {
            background: #dc3545;
            color: white;
        }
        .btn-danger:hover {
            background: #c82333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        .search-box {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        .search-box input {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 16px;
        }
        .search-box input:focus {
            outline: none;
            border-color: #667eea;
        }
        .folders {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        .folder-container {
            background: white;
            padding: 15px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            transition: all 0.2s;
            position: relative;
        }
        .folder-container:hover {
            border-color: #667eea;
            background: #f0f4ff;
        }
        .folder-container.active {
            border-color: #667eea;
            background: #f0f4ff;
        }
        .folder-btn {
            background: none;
            border: none;
            cursor: pointer;
            text-align: left;
            font-size: 14px;
            color: #333;
            width: 100%;
            padding: 0;
        }
        .folder-btn .count {
            color: #999;
            font-size: 12px;
            margin-top: 5px;
        }
        .folder-actions {
            display: none;
            gap: 5px;
            margin-top: 8px;
            justify-content: flex-end;
        }
        .folder-container.active .folder-actions {
            display: flex;
        }
        .folder-actions button {
            background: #6c757d;
            color: white;
            border: none;
            padding: 4px 8px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 11px;
        }
        .folder-actions button:hover {
            background: #5a6268;
        }
        .folder-actions button.folder-delete {
            background: #dc3545;
        }
        .folder-actions button.folder-delete:hover {
            background: #c82333;
        }
        .add-folder-btn {
            background: white;
            padding: 15px;
            border: 2px dashed #667eea;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s;
            text-align: center;
            font-size: 14px;
            color: #667eea;
            font-weight: 500;
        }
        .add-folder-btn:hover {
            background: #f0f4ff;
            border-color: #5568d3;
        }
        .items {
            display: grid;
            gap: 15px;
        }
        .item {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            border-left: 4px solid #667eea;
            position: relative;
        }
        .item.age-warning {
            border-left-color: #ffc107;
        }
        .item.age-critical {
            border-left-color: #dc3545;
        }
        .age-badge {
            position: absolute;
            bottom: 15px;
            left: 15px;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
        }
        .age-badge.warning {
            background: #fff3cd;
            color: #856404;
        }
        .age-badge.critical {
            background: #f8d7da;
            color: #721c24;
        }
        .item-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 12px;
        }
        .item-title {
            flex: 1;
        }
        .item-name {
            font-size: 18px;
            font-weight: 600;
            color: #333;
            margin-bottom: 4px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .item-url {
            font-size: 13px;
            color: #667eea;
            text-decoration: none;
            word-break: break-all;
        }
        .item-url:hover {
            text-decoration: underline;
        }
        .item-actions {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }
        .item-actions button {
            background: #6c757d;
            color: white;
            border: none;
            padding: 4px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
        }
        .item-actions button:hover {
            background: #5a6268;
        }
        .item-actions button.delete {
            background: #dc3545;
        }
        .item-actions button.delete:hover {
            background: #c82333;
        }
        .favorite {
            color: #ffc107;
            font-size: 20px;
            cursor: pointer;
            border: none;
            background: none;
            padding: 0;
        }
        .favorite:hover {
            transform: scale(1.1);
        }
        .credentials {
            background: #f8f9fa;
            padding: 12px;
            border-radius: 6px;
            margin-top: 12px;
        }
        .cred-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid #e0e0e0;
        }
        .cred-row:last-child {
            border-bottom: none;
        }
        .cred-label {
            font-size: 12px;
            color: #666;
            font-weight: 600;
            text-transform: uppercase;
            width: 100px;
        }
        .cred-value {
            flex: 1;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            color: #333;
            word-break: break-all;
        }
        .cred-value.password {
            filter: blur(4px);
            transition: filter 0.2s;
            cursor: pointer;
        }
        .cred-value.password:hover {
            filter: blur(0);
        }
        .copy-btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            margin-left: 10px;
        }
        .copy-btn:hover {
            background: #5568d3;
        }
        .copy-btn.copied {
            background: #28a745;
        }
        .notes {
            margin-top: 12px;
            padding: 12px;
            background: #fffbea;
            border-radius: 6px;
            font-size: 14px;
            color: #666;
            white-space: pre-wrap;
        }
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #999;
        }
        .empty-state-icon {
            font-size: 64px;
            margin-bottom: 20px;
        }

        /* Modal Styles */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
            overflow-y: auto;
        }
        .modal.active {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .modal-content {
            background: white;
            padding: 30px;
            border-radius: 10px;
            width: 90%;
            max-width: 500px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            max-height: 90vh;
            overflow-y: auto;
        }
        .modal-header {
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 20px;
            color: #333;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 500;
            font-size: 14px;
        }
        .form-group input, .form-group select, .form-group textarea {
            width: 100%;
            padding: 10px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 14px;
            font-family: inherit;
        }
        .form-group input:focus, .form-group select:focus, .form-group textarea:focus {
            outline: none;
            border-color: #667eea;
        }
        .form-group textarea {
            resize: vertical;
            min-height: 80px;
        }
        .password-generator {
            display: flex;
            gap: 8px;
            margin-top: 8px;
        }
        .password-generator button {
            padding: 8px 16px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
        }
        .password-generator button:hover {
            background: #5568d3;
        }
        .password-options {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin-top: 10px;
        }
        .password-options label {
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 13px;
            font-weight: normal;
        }
        .password-options input[type="checkbox"] {
            width: auto;
        }
        .password-options input[type="number"] {
            width: 80px;
            padding: 6px;
        }
        .modal-actions {
            display: flex;
            gap: 10px;
            justify-content: flex-end;
            margin-top: 25px;
        }
        .btn-secondary {
            background: #6c757d;
            color: white;
        }
        .btn-secondary:hover {
            background: #5a6268;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 Password Manager</h1>
        <div class="header-actions">
            <button type="button" class="btn btn-primary" onclick="alert('Test: JS works!'); openNewItemModal();">➕ New Password</button>
            <button type="button" onclick="alert('Simple test works!')" style="background: orange; color: white; padding: 8px 16px; border: none; border-radius: 4px; margin-right: 10px;">TEST JS</button>
            <a href="{{ url_for('logout') }}" class="btn btn-danger">Logout</a>
        </div>
    </div>

    <div class="container">
        <div class="search-box">
            <input type="text" id="searchInput" placeholder="🔍 Search passwords..." onkeyup="filterItems()">
        </div>

        <div class="folders">
            <div class="folder-container active">
                <button type="button" class="folder-btn" onclick="filterByFolder(null, this)">
                    📁 All Items
                    <div class="count">{{ total_items }} items</div>
                </button>
            </div>
            {% for folder in folders %}
            <div class="folder-container" data-folder-id="{{ folder.id }}">
                <button type="button" class="folder-btn" onclick="console.log('Folder clicked:', '{{ folder.id }}'); if(typeof filterByFolder === 'function') { filterByFolder('{{ folder.id }}', this); } else { alert('filterByFolder not found'); }">
                    📂 {{ folder.name }}
                    <div class="count">{{ folder.count }} items</div>
                </button>
                <div class="folder-actions">
                    <button type="button" class="folder-edit" onclick="console.log('Edit folder clicked'); if(typeof openEditFolderModal === 'function') { openEditFolderModal('{{ folder.id }}', {{ folder.name|tojson }}); } else { alert('openEditFolderModal not found'); }">Edit</button>
                    <button type="button" class="folder-delete" onclick="console.log('Delete folder clicked'); if(typeof deleteFolder === 'function') { deleteFolder('{{ folder.id }}', {{ folder.name|tojson }}, {{ folder.count }}); } else { alert('deleteFolder not found'); }">Delete</button>
                </div>
            </div>
            {% endfor %}
            <div class="add-folder-btn" onclick="openAddFolderModal()">
                ➕ Add Folder
            </div>
        </div>

        <div class="items" id="itemsList">
            {% if items %}
                {% for item in items %}
                {% set age_days = item.age_days %}
                {% set age_warning = item.age_warning %}
                <div class="item {% if age_warning == 'critical' %}age-critical{% elif age_warning == 'warning' %}age-warning{% endif %}"
                     data-folder="{{ item.folder_id or '' }}"
                     data-name="{{ item.name.lower() }}"
                     data-username="{{ (item.username or '').lower() }}"
                     data-item-id="{{ item.id }}"
                     data-item-name="{{ item.name|e }}"
                     data-item-folder="{{ item.folder_id or '' }}"
                     data-item-uri="{{ (item.uri or '')|e }}"
                     data-item-username="{{ (item.username or '')|e }}"
                     data-item-password="{{ (item.password or '')|e }}"
                     data-item-notes="{{ (item.notes or '')|e }}"
                     data-item-favorite="{{ item.favorite }}">

                    {% if age_warning %}
                    <div class="age-badge {{ age_warning }}">
                        {% if age_warning == 'critical' %}
                        ⚠️ {{ age_days }} days old
                        {% else %}
                        ⏰ {{ age_days }} days old
                        {% endif %}
                    </div>
                    {% endif %}

                    <div class="item-header">
                        <div class="item-title">
                            <div class="item-name">
                                <button type="button" class="favorite" onclick="toggleFavorite('{{ item.id }}', {{ item.favorite }})">
                                    {% if item.favorite %}⭐{% else %}☆{% endif %}
                                </button>
                                {{ item.name }}
                            </div>
                            {% if item.uri %}
                            <a href="{{ item.uri }}" target="_blank" class="item-url">{{ item.uri }}</a>
                            {% endif %}
                        </div>
                        <div class="item-actions">
                            <button type="button" onclick="console.log('Edit clicked'); if(typeof openEditModal === 'function') { openEditModal('{{ item.id }}', {{ item.name|tojson }}, {{ (item.folder_id or '')|tojson }}, {{ (item.uri or '')|tojson }}, {{ (item.username or '')|tojson }}, {{ (item.password or '')|tojson }}, {{ (item.notes or '')|tojson }}); } else { alert('openEditModal not found'); }">Edit</button>
                            <button type="button" onclick="console.log('Move clicked'); if(typeof openMoveModal === 'function') { openMoveModal('{{ item.id }}', {{ item.name|tojson }}, {{ (item.folder_id or '')|tojson }}); } else { alert('openMoveModal not found'); }">Move</button>
                            <button type="button" class="delete" onclick="console.log('Delete clicked'); if(typeof deleteItem === 'function') { deleteItem('{{ item.id }}', {{ item.name|tojson }}); } else { alert('deleteItem not found'); }">Delete</button>
                        </div>
                    </div>

                    <div class="credentials">
                        {% if item.username %}
                        <div class="cred-row">
                            <span class="cred-label">Username</span>
                            <span class="cred-value">{{ item.username }}</span>
                            <button type="button" class="copy-btn" onclick="console.log('Copy username clicked'); if(typeof copyToClipboard === 'function') { copyToClipboard({{ item.username|tojson }}, this); } else { alert('copyToClipboard not found'); }">Copy</button>
                        </div>
                        {% endif %}

                        {% if item.password %}
                        <div class="cred-row">
                            <span class="cred-label">Password</span>
                            <span class="cred-value password" title="Click to reveal">{{ item.password }}</span>
                            <button type="button" class="copy-btn" onclick="console.log('Copy password clicked'); if(typeof copyToClipboard === 'function') { copyToClipboard({{ item.password|tojson }}, this); } else { alert('copyToClipboard not found'); }">Copy</button>
                        </div>
                        {% endif %}
                    </div>

                    {% if item.notes %}
                    <div class="notes">{{ item.notes }}</div>
                    {% endif %}
                </div>
                {% endfor %}
            {% else %}
                <div class="empty-state">
                    <div class="empty-state-icon">🔍</div>
                    <h2>No passwords found</h2>
                    <p>Try a different search or folder</p>
                </div>
            {% endif %}
        </div>
    </div>

    <!-- New Item Modal -->
    <div id="newItemModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">➕ Add New Password</div>
            <form method="POST" action="{{ url_for('add_item') }}">
                <div class="form-group">
                    <label for="name">Name *</label>
                    <input type="text" id="name" name="name" required>
                </div>
                <div class="form-group">
                    <label for="folder">Folder</label>
                    <select id="folder" name="folder_id">
                        <option value="">No Folder</option>
                        {% for folder in folders %}
                        <option value="{{ folder.id }}">{{ folder.name }}</option>
                        {% endfor %}
                    </select>
                </div>
                <div class="form-group">
                    <label for="url">Website URL</label>
                    <input type="url" id="url" name="url" placeholder="https://example.com">
                </div>
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username">
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="text" id="password" name="password">
                    <div class="password-generator">
                        <button type="button" onclick="generatePassword('password')">🎲 Generate</button>
                    </div>
                    <div class="password-options">
                        <label><input type="number" id="pwdLength" value="16" min="8" max="64"> Length</label>
                        <label><input type="checkbox" id="pwdUpper" checked> Uppercase</label>
                        <label><input type="checkbox" id="pwdLower" checked> Lowercase</label>
                        <label><input type="checkbox" id="pwdNumbers" checked> Numbers</label>
                        <label><input type="checkbox" id="pwdSymbols" checked> Symbols</label>
                    </div>
                </div>
                <div class="form-group">
                    <label for="notes">Notes</label>
                    <textarea id="notes" name="notes"></textarea>
                </div>
                <div class="modal-actions">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('newItemModal')">Cancel</button>
                    <button type="submit" class="btn btn-primary">Save</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Edit Item Modal -->
    <div id="editItemModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">✏️ Edit Password</div>
            <form method="POST" action="{{ url_for('edit_item') }}">
                <input type="hidden" id="editItemId" name="item_id">
                <div class="form-group">
                    <label for="editName">Name *</label>
                    <input type="text" id="editName" name="name" required>
                </div>
                <div class="form-group">
                    <label for="editFolder">Folder</label>
                    <select id="editFolder" name="folder_id">
                        <option value="">No Folder</option>
                        {% for folder in folders %}
                        <option value="{{ folder.id }}">{{ folder.name }}</option>
                        {% endfor %}
                    </select>
                </div>
                <div class="form-group">
                    <label for="editUrl">Website URL</label>
                    <input type="url" id="editUrl" name="url" placeholder="https://example.com">
                </div>
                <div class="form-group">
                    <label for="editUsername">Username</label>
                    <input type="text" id="editUsername" name="username">
                </div>
                <div class="form-group">
                    <label for="editPassword">Password</label>
                    <input type="text" id="editPassword" name="password">
                    <div class="password-generator">
                        <button type="button" onclick="generatePassword('editPassword')">🎲 Generate</button>
                    </div>
                </div>
                <div class="form-group">
                    <label for="editNotes">Notes</label>
                    <textarea id="editNotes" name="notes"></textarea>
                </div>
                <div class="modal-actions">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('editItemModal')">Cancel</button>
                    <button type="submit" class="btn btn-primary">Save Changes</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Move Item Modal -->
    <div id="moveItemModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">📁 Move Password</div>
            <form method="POST" action="{{ url_for('move_item') }}">
                <input type="hidden" id="moveItemId" name="item_id">
                <div class="form-group">
                    <label>Moving: <strong id="moveItemName"></strong></label>
                </div>
                <div class="form-group">
                    <label for="moveFolder">Move to Folder</label>
                    <select id="moveFolder" name="folder_id">
                        <option value="">No Folder</option>
                        {% for folder in folders %}
                        <option value="{{ folder.id }}">{{ folder.name }}</option>
                        {% endfor %}
                    </select>
                </div>
                <div class="modal-actions">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('moveItemModal')">Cancel</button>
                    <button type="submit" class="btn btn-primary">Move</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Add Folder Modal -->
    <div id="addFolderModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">➕ Add Folder</div>
            <form method="POST" action="{{ url_for('add_folder') }}">
                <div class="form-group">
                    <label for="folderName">Folder Name *</label>
                    <input type="text" id="folderName" name="name" required autofocus>
                </div>
                <div class="modal-actions">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('addFolderModal')">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create Folder</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Edit Folder Modal -->
    <div id="editFolderModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">✏️ Edit Folder</div>
            <form method="POST" action="{{ url_for('edit_folder') }}">
                <input type="hidden" id="editFolderId" name="folder_id">
                <div class="form-group">
                    <label for="editFolderName">Folder Name *</label>
                    <input type="text" id="editFolderName" name="name" required autofocus>
                </div>
                <div class="modal-actions">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('editFolderModal')">Cancel</button>
                    <button type="submit" class="btn btn-primary">Save Changes</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        // Debug: Test if JavaScript is running
        console.log('JavaScript loaded');
        
        // Make sure functions are in global scope
        window.copyToClipboard = function(text, btn) {
            navigator.clipboard.writeText(text).then(function() {
                var originalText = btn.textContent;
                btn.textContent = '✓ Copied';
                btn.classList.add('copied');
                setTimeout(function() {
                    btn.textContent = originalText;
                    btn.classList.remove('copied');
                }, 2000);
            });
        }

        var currentFolder = null;

        window.filterByFolder = function(folderId, btn) {
            currentFolder = folderId;
            var containers = document.querySelectorAll('.folder-container');
            for (var i = 0; i < containers.length; i++) {
                containers[i].classList.remove('active');
            }
            if (btn && btn.parentElement) {
                btn.parentElement.classList.add('active');
            }
            filterItems();
        }

        window.openAddFolderModal = function() {
            document.getElementById('addFolderModal').classList.add('active');
        }

        window.openEditFolderModal = function(folderId, folderName) {
            document.getElementById('editFolderId').value = folderId;
            document.getElementById('editFolderName').value = folderName;
            document.getElementById('editFolderModal').classList.add('active');
        }

        window.deleteFolder = function(folderId, folderName, itemCount) {
            var message = 'Are you sure you want to delete the folder "' + folderName + '"?';
            if (itemCount > 0) {
                message += '\n\nThis folder contains ' + itemCount + ' item(s). All items will be moved to "No Folder".';
            }
            if (confirm(message)) {
                fetch('/delete_folder', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        folder_id: folderId
                    })
                }).then(function(response) {
                    if (response.ok) {
                        location.reload();
                    } else {
                        alert('Error deleting folder. Please try again.');
                    }
                }).catch(function(error) {
                    console.error('Error deleting folder:', error);
                    alert('Error deleting folder. Please try again.');
                });
            }
        }

        window.filterItems = function() {
            var searchTerm = document.getElementById('searchInput').value.toLowerCase();
            var items = document.querySelectorAll('.item');
            var visibleCount = 0;

            for (var i = 0; i < items.length; i++) {
                var item = items[i];
                var name = item.dataset.name;
                var username = item.dataset.username;
                var folder = item.dataset.folder;

                var matchesSearch = name.indexOf(searchTerm) !== -1 || username.indexOf(searchTerm) !== -1;
                var matchesFolder = !currentFolder || folder === currentFolder;

                if (matchesSearch && matchesFolder) {
                    item.style.display = 'block';
                    visibleCount++;
                } else {
                    item.style.display = 'none';
                }
            }
        }

        window.generatePassword = function(fieldId) {
            var length = parseInt(document.getElementById('pwdLength').value) || 16;
            var useUpper = document.getElementById('pwdUpper').checked;
            var useLower = document.getElementById('pwdLower').checked;
            var useNumbers = document.getElementById('pwdNumbers').checked;
            var useSymbols = document.getElementById('pwdSymbols').checked;

            var chars = '';
            if (useUpper) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
            if (useLower) chars += 'abcdefghijklmnopqrstuvwxyz';
            if (useNumbers) chars += '0123456789';
            if (useSymbols) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';

            if (!chars) chars = 'abcdefghijklmnopqrstuvwxyz';

            var password = '';
            var array = new Uint32Array(length);
            crypto.getRandomValues(array);

            for (var i = 0; i < length; i++) {
                password += chars[array[i] % chars.length];
            }

            document.getElementById(fieldId).value = password;
        }

        window.openNewItemModal = function() {
            document.getElementById('newItemModal').classList.add('active');
        }

        window.openEditModal = function(id, name, folderId, url, username, password, notes) {
            try {
                document.getElementById('editItemId').value = id || '';
                document.getElementById('editName').value = name || '';
                document.getElementById('editFolder').value = folderId || '';
                document.getElementById('editUrl').value = url || '';
                document.getElementById('editUsername').value = username || '';
                document.getElementById('editPassword').value = password || '';
                document.getElementById('editNotes').value = notes || '';
                document.getElementById('editItemModal').classList.add('active');
            } catch (e) {
                console.error('Error opening edit modal:', e);
                alert('Error opening edit form. Please try again.');
            }
        }

        window.openMoveModal = function(itemId, itemName, currentFolderId) {
            try {
                document.getElementById('moveItemId').value = itemId || '';
                document.getElementById('moveItemName').textContent = itemName || '';
                document.getElementById('moveFolder').value = currentFolderId || '';
                document.getElementById('moveItemModal').classList.add('active');
            } catch (e) {
                console.error('Error opening move modal:', e);
                alert('Error opening move form. Please try again.');
            }
        }

        window.closeModal = function(modalId) {
            document.getElementById(modalId).classList.remove('active');
        }

        window.toggleFavorite = function(itemId, currentFavorite) {
            fetch('/toggle_favorite', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    item_id: itemId,
                    favorite: currentFavorite ? 0 : 1
                })
            }).then(function() {
                location.reload();
            });
        }

        window.deleteItem = function(itemId, itemName) {
            try {
                if (confirm('Are you sure you want to delete "' + itemName + '"?')) {
                    fetch('/delete_item', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            item_id: itemId
                        })
                    }).then(function(response) {
                        if (response.ok) {
                            location.reload();
                        } else {
                            alert('Error deleting item. Please try again.');
                        }
                    }).catch(function(error) {
                        console.error('Error deleting item:', error);
                        alert('Error deleting item. Please try again.');
                    });
                }
            } catch (e) {
                console.error('Error in deleteItem:', e);
                alert('Error deleting item. Please try again.');
            }
        }


        // Close modal when clicking outside
        window.onclick = function(event) {
            // Only handle clicks on the modal background, not on buttons or other elements
            if (event.target.classList && event.target.classList.contains('modal')) {
                event.target.classList.remove('active');
            }
        }
    </script>
</body>
</html>
"""


@app.route('/')
def index():
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')

        # Try to connect to database
        conn = get_db_connection(password)
        if conn:
            session['authenticated'] = True
            session['db_password'] = password
            session.permanent = True
            conn.close()
            return redirect(url_for('dashboard'))
        else:
            return render_template_string(LOGIN_TEMPLATE, error='Invalid master password')

    return render_template_string(LOGIN_TEMPLATE)


@app.route('/dashboard')
@login_required
def dashboard():
    password = session.get('db_password')
    conn = get_db_connection(password)

    if not conn:
        session.clear()
        return redirect(url_for('login'))

    cursor = conn.cursor()

    # Get folders with item counts
    cursor.execute("""
        SELECT f.id, f.name, COUNT(i.id) as count
        FROM folders f
        LEFT JOIN items i ON f.id = i.folder_id
        GROUP BY f.id, f.name
        ORDER BY f.name
    """)
    folders = cursor.fetchall()

    # Get all items with their first URI and calculate age
    cursor.execute("""
        SELECT i.*, u.uri
        FROM items i
        LEFT JOIN uris u ON i.id = u.item_id
        GROUP BY i.id
        ORDER BY i.favorite DESC, i.name
    """)
    items_raw = cursor.fetchall()

    # Add age calculation to items
    items = []
    for item in items_raw:
        item_dict = dict(item)
        age_days = calculate_password_age(item['revision_date'])
        item_dict['age_days'] = age_days
        item_dict['age_warning'] = get_age_warning(age_days)
        items.append(item_dict)

    cursor.execute("SELECT COUNT(*) FROM items")
    total_items = cursor.fetchone()[0]

    conn.close()

    return render_template_string(MAIN_TEMPLATE,
                                 folders=folders,
                                 items=items,
                                 total_items=total_items)


@app.route('/add_item', methods=['POST'])
@login_required
def add_item():
    password = session.get('db_password')
    conn = get_db_connection(password)

    if not conn:
        session.clear()
        return redirect(url_for('login'))

    cursor = conn.cursor()

    # Generate new UUID for item
    item_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat() + 'Z'

    # Get form data
    name = request.form.get('name')
    folder_id = request.form.get('folder_id') or None
    url = request.form.get('url')
    username = request.form.get('username')
    password_value = request.form.get('password')
    notes = request.form.get('notes')

    # Insert item
    cursor.execute("""
        INSERT INTO items
        (id, folder_id, name, username, password, notes, favorite, reprompt, type, created_date, revision_date)
        VALUES (?, ?, ?, ?, ?, ?, 0, 0, 1, ?, ?)
    """, (item_id, folder_id, name, username, password_value, notes, now, now))

    # Insert URI if provided
    if url:
        cursor.execute("""
            INSERT INTO uris (item_id, uri)
            VALUES (?, ?)
        """, (item_id, url))

    conn.commit()
    conn.close()

    return redirect(url_for('dashboard'))


@app.route('/edit_item', methods=['POST'])
@login_required
def edit_item():
    password = session.get('db_password')
    conn = get_db_connection(password)

    if not conn:
        session.clear()
        return redirect(url_for('login'))

    cursor = conn.cursor()

    item_id = request.form.get('item_id')
    name = request.form.get('name')
    folder_id = request.form.get('folder_id') or None
    url = request.form.get('url')
    username = request.form.get('username')
    password_value = request.form.get('password')
    notes = request.form.get('notes')
    now = datetime.utcnow().isoformat() + 'Z'

    # Update item
    cursor.execute("""
        UPDATE items
        SET name = ?, folder_id = ?, username = ?, password = ?, notes = ?, revision_date = ?
        WHERE id = ?
    """, (name, folder_id, username, password_value, notes, now, item_id))

    # Update or insert URI
    cursor.execute("DELETE FROM uris WHERE item_id = ?", (item_id,))
    if url:
        cursor.execute("INSERT INTO uris (item_id, uri) VALUES (?, ?)", (item_id, url))

    conn.commit()
    conn.close()

    return redirect(url_for('dashboard'))


@app.route('/move_item', methods=['POST'])
@login_required
def move_item():
    password = session.get('db_password')
    conn = get_db_connection(password)

    if not conn:
        session.clear()
        return redirect(url_for('login'))

    cursor = conn.cursor()

    item_id = request.form.get('item_id')
    folder_id = request.form.get('folder_id') or None
    now = datetime.utcnow().isoformat() + 'Z'

    # Update item folder
    cursor.execute("""
        UPDATE items
        SET folder_id = ?, revision_date = ?
        WHERE id = ?
    """, (folder_id, now, item_id))

    conn.commit()
    conn.close()

    return redirect(url_for('dashboard'))


@app.route('/toggle_favorite', methods=['POST'])
@login_required
def toggle_favorite():
    password = session.get('db_password')
    conn = get_db_connection(password)

    if not conn:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json()
    item_id = data.get('item_id')
    favorite = data.get('favorite')
    now = datetime.utcnow().isoformat() + 'Z'

    cursor = conn.cursor()
    cursor.execute("""
        UPDATE items
        SET favorite = ?, revision_date = ?
        WHERE id = ?
    """, (favorite, now, item_id))

    conn.commit()
    conn.close()

    return jsonify({'success': True})


@app.route('/delete_item', methods=['POST'])
@login_required
def delete_item():
    password = session.get('db_password')
    conn = get_db_connection(password)

    if not conn:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json()
    item_id = data.get('item_id')

    cursor = conn.cursor()

    # Delete related records first
    cursor.execute("DELETE FROM uris WHERE item_id = ?", (item_id,))
    cursor.execute("DELETE FROM fields WHERE item_id = ?", (item_id,))
    cursor.execute("DELETE FROM items WHERE id = ?", (item_id,))

    conn.commit()
    conn.close()

    return jsonify({'success': True})


@app.route('/add_folder', methods=['POST'])
@login_required
def add_folder():
    password = session.get('db_password')
    conn = get_db_connection(password)

    if not conn:
        session.clear()
        return redirect(url_for('login'))

    cursor = conn.cursor()
    folder_name = request.form.get('name')

    if not folder_name:
        conn.close()
        return redirect(url_for('dashboard'))

    # Generate new UUID for folder
    folder_id = str(uuid.uuid4())

    # Insert folder
    cursor.execute("""
        INSERT INTO folders (id, name)
        VALUES (?, ?)
    """, (folder_id, folder_name))

    conn.commit()
    conn.close()

    return redirect(url_for('dashboard'))


@app.route('/edit_folder', methods=['POST'])
@login_required
def edit_folder():
    password = session.get('db_password')
    conn = get_db_connection(password)

    if not conn:
        session.clear()
        return redirect(url_for('login'))

    cursor = conn.cursor()
    folder_id = request.form.get('folder_id')
    folder_name = request.form.get('name')

    if not folder_id or not folder_name:
        conn.close()
        return redirect(url_for('dashboard'))

    # Update folder name
    cursor.execute("""
        UPDATE folders
        SET name = ?
        WHERE id = ?
    """, (folder_name, folder_id))

    conn.commit()
    conn.close()

    return redirect(url_for('dashboard'))


@app.route('/delete_folder', methods=['POST'])
@login_required
def delete_folder():
    password = session.get('db_password')
    conn = get_db_connection(password)

    if not conn:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json()
    folder_id = data.get('folder_id')

    if not folder_id:
        return jsonify({'error': 'Folder ID required'}), 400

    cursor = conn.cursor()

    # Move all items in this folder to "No Folder" (set folder_id to NULL)
    cursor.execute("""
        UPDATE items
        SET folder_id = NULL, revision_date = ?
        WHERE folder_id = ?
    """, (datetime.utcnow().isoformat() + 'Z', folder_id))

    # Delete the folder
    cursor.execute("DELETE FROM folders WHERE id = ?", (folder_id,))

    conn.commit()
    conn.close()

    return jsonify({'success': True})


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    if not os.path.exists(DB_PATH):
        print(f"Error: Database file '{DB_PATH}' not found!")
        print("Run import_bitwarden.py first to create the database.")
        exit(1)

    print("\n" + "="*60)
    print("🔐 Password Manager Starting...")
    print("="*60)
    print("\nAccess the password manager at:")
    print("  • From this device: http://127.0.0.1:5000")
    print("  • From local network: http://<phone-ip>:5000")
    print("\nTo find your phone's IP address:")
    print("  ifconfig wlan0 | grep inet")
    print("\n" + "="*60 + "\n")

    # Bind to 0.0.0.0 to allow network access
    app.run(host='0.0.0.0', port=5000, debug=False)
