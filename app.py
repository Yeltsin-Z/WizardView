#!/usr/bin/env python3
"""
WizardView - Gandalf's tool for regression clarity
Compare regression test scrolls from GitHub Actions
Compare, analyze, and illuminate test differences
"""

import os
import sys
import zipfile
import shutil
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_from_directory, send_file, session, redirect, url_for, flash
import csv
from io import StringIO, BytesIO
from difflib import unified_diff, SequenceMatcher
import json
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import base64

app = Flask(__name__)

# SECRET_KEY is required for session security
# Must be set via environment variable in production
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    # In development, use a default key with warning
    if os.environ.get('FLASK_ENV') == 'development' or __name__ == '__main__':
        SECRET_KEY = 'dev-secret-key-INSECURE-change-for-production'
        print("⚠️  WARNING: Using insecure development SECRET_KEY!", flush=True)
    else:
        raise ValueError("SECRET_KEY environment variable must be set in production!")

app.secret_key = SECRET_KEY

# Linear Configuration
# Set these as environment variables in production
LINEAR_API_KEY = os.environ.get('LINEAR_API_KEY')
LINEAR_API_URL = 'https://api.linear.app/graphql'
LINEAR_TEAM_ID = os.environ.get('LINEAR_TEAM_ID', 'ENG')  # Default to ENG team

# Configuration
UPLOAD_FOLDER = Path(__file__).parent / "uploads"
UPLOAD_FOLDER.mkdir(exist_ok=True)

# Use environment variable or default to uploads/extracted
# This makes it work on both local and deployed environments
default_artifacts = UPLOAD_FOLDER / "extracted"
ARTIFACTS_DIR = Path(os.getenv('ARTIFACTS_DIR', str(default_artifacts)))

# For local development convenience, allow DEV_ARTIFACTS_PATH
# This is ONLY used if explicitly set via environment variable
dev_artifacts_override = os.getenv('DEV_ARTIFACTS_PATH')
if dev_artifacts_override:
    dev_path = Path(dev_artifacts_override)
    if dev_path.exists():
        print(f"⚠️  DEV MODE: Using DEV_ARTIFACTS_PATH: {dev_path}", flush=True)
        ARTIFACTS_DIR = dev_path
    else:
        print(f"⚠️  DEV_ARTIFACTS_PATH set but doesn't exist: {dev_path}", flush=True)

print(f"✅ Artifacts directory: {ARTIFACTS_DIR}", flush=True)

# Directory for storing ZIP files for Linear attachments
LINEAR_ATTACHMENTS_DIR = Path(__file__).parent / 'linear_attachments'
LINEAR_ATTACHMENTS_DIR.mkdir(exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# User authentication configuration
# Can be overridden with environment variables for production
# Format: USERNAME=email PASSWORD=plaintext (will be hashed)
DEFAULT_USERNAME = os.getenv('AUTH_USERNAME', 'sdet-team@drivetrain.ai')
DEFAULT_PASSWORD = os.getenv('AUTH_PASSWORD', 'OneRing2RuleThemAll')

# Simple user storage (in production, use a database or SSO)
# Password is hashed using werkzeug.security
USERS = {
    DEFAULT_USERNAME: generate_password_hash(DEFAULT_PASSWORD),
}

print(f"✅ Authentication configured for user: {DEFAULT_USERNAME}", flush=True)

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            # Check if this is an API request (JSON expected)
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required', 'redirect': '/login'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def extract_artifact(zip_path, extract_to):
    """
    Extract scroll bundle zip file and normalize to standard format.
    
    Supports two formats:
    - Format 1 (Old): folder/main/FILE.csv and folder/feat/FILE.csv
    - Format 2 (New): folder/main-FILE and folder/feat-FILE
    
    Both are normalized to Format 2 internally.
    """
    import shutil
    import tempfile
    
    # Use system temp directory to avoid conflicts
    temp_extract = Path(tempfile.mkdtemp(prefix='wizardview_'))
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_extract)
            
        # Detect format and normalize
        print(f"📦 Analyzing artifact structure...", flush=True)
        
        for folder in temp_extract.iterdir():
            if not folder.is_dir():
                continue
                
            folder_id = folder.name
            target_folder = Path(extract_to) / folder_id
            target_folder.mkdir(parents=True, exist_ok=True)
            
            # Check if this is Format 1 (has main/ and feat/ subdirectories)
            main_dir = folder / 'main'
            feat_dir = folder / 'feat'
            
            if main_dir.exists() and feat_dir.exists():
                # Format 1: Convert folder/main/FILE.csv → folder/main-FILE
                print(f"   Format 1 detected for tenant {folder_id} (main/ and feat/ subdirs)", flush=True)
                
                # Process main files
                for file_path in main_dir.iterdir():
                    if file_path.is_file():
                        # Remove .csv extension if present
                        file_name = file_path.stem if file_path.suffix == '.csv' else file_path.name
                        target_path = target_folder / f"main-{file_name}"
                        shutil.copy2(file_path, target_path)
                        print(f"      ✓ Converted: {file_path.name} → main-{file_name}", flush=True)
                
                # Process feat files
                for file_path in feat_dir.iterdir():
                    if file_path.is_file():
                        # Remove .csv extension if present
                        file_name = file_path.stem if file_path.suffix == '.csv' else file_path.name
                        target_path = target_folder / f"feat-{file_name}"
                        shutil.copy2(file_path, target_path)
                        print(f"      ✓ Converted: {file_path.name} → feat-{file_name}", flush=True)
            else:
                # Format 2: Files are already named main-FILE and feat-FILE
                print(f"   Format 2 detected for tenant {folder_id} (flat structure)", flush=True)
                for file_path in folder.iterdir():
                    if file_path.is_file():
                        target_path = target_folder / file_path.name
                        shutil.copy2(file_path, target_path)
                        print(f"      ✓ Copied: {file_path.name}", flush=True)
        
        print(f"✅ Artifact extraction complete!\n", flush=True)
        
    finally:
        # Always clean up temp directory
        try:
            shutil.rmtree(temp_extract)
            print(f"🧹 Cleaned up temp directory", flush=True)
        except Exception as e:
            print(f"⚠️ Failed to clean temp directory: {e}", flush=True)
    
    return extract_to


def get_artifact_structure(base_path):
    """
    Get the structure of the scroll directory
    Returns: {folder_id: [file_pairs]}
    """
    base_path = Path(base_path)
    structure = {}
    
    if not base_path.exists():
        return structure
    
    # Get all subdirectories (like 508, 561, etc.)
    for folder in sorted(base_path.iterdir()):
        if folder.is_dir():
            folder_id = folder.name
            files = sorted([f.name for f in folder.iterdir() if f.is_file()])
            
            # Group files by their base ID (e.g., CHART-426)
            # Supports normalized format: feat-CHART-426 and main-CHART-426
            file_groups = {}
            for file_name in files:
                # Check for normalized format (prefix): feat-FILE or main-FILE
                if file_name.startswith('feat-'):
                    base_id = file_name[5:]  # Remove 'feat-' prefix
                    if base_id not in file_groups:
                        file_groups[base_id] = {}
                    file_groups[base_id]['feat'] = file_name
                elif file_name.startswith('main-'):
                    base_id = file_name[5:]  # Remove 'main-' prefix
                    if base_id not in file_groups:
                        file_groups[base_id] = {}
                    file_groups[base_id]['main'] = file_name
                # Fallback: Check for legacy format (suffix): FILE-feat or FILE-main
                elif file_name.endswith('-feat'):
                    base_id = file_name[:-5]  # Remove '-feat' suffix
                    if base_id not in file_groups:
                        file_groups[base_id] = {}
                    file_groups[base_id]['feat'] = file_name
                elif file_name.endswith('-main'):
                    base_id = file_name[:-5]  # Remove '-main' suffix
                    if base_id not in file_groups:
                        file_groups[base_id] = {}
                    file_groups[base_id]['main'] = file_name
            
            structure[folder_id] = file_groups
    
    return structure


def read_csv_file(file_path):
    """Read CSV file and return as list of rows"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            return content.splitlines()
    except Exception as e:
        return [f"Error reading file: {str(e)}"]


def parse_csv_row(row):
    """Parse CSV row into structured data"""
    parts = row.split(',')
    return {
        'raw': row,
        'parts': parts
    }


def calculate_diff_stats(main_content, feat_content):
    """
    Intelligently calculate diff statistics using SequenceMatcher
    Returns accurate counts of added, removed, modified, and unchanged lines
    """
    from difflib import SequenceMatcher
    
    main_lines = main_content.splitlines()
    feat_lines = feat_content.splitlines()
    
    # Initialize counters
    added = 0
    removed = 0
    modified = 0
    unchanged = 0
    
    # Use SequenceMatcher for accurate line-by-line comparison
    matcher = SequenceMatcher(None, main_lines, feat_lines)
    
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == 'equal':
            # Lines are identical
            unchanged += (i2 - i1)
        elif tag == 'delete':
            # Lines only in main (removed in feat)
            removed += (i2 - i1)
        elif tag == 'insert':
            # Lines only in feat (added in feat)
            added += (j2 - j1)
        elif tag == 'replace':
            # Lines exist in both but are different (modified)
            # Count the number of modified lines as the minimum of the two ranges
            # The difference goes to added or removed
            main_count = i2 - i1
            feat_count = j2 - j1
            
            if main_count == feat_count:
                # Same number of lines, all modified
                modified += main_count
            elif main_count > feat_count:
                # More lines in main, some were modified, some were removed
                modified += feat_count
                removed += (main_count - feat_count)
            else:
                # More lines in feat, some were modified, some were added
                modified += main_count
                added += (feat_count - main_count)
    
    return {
        'unchanged': unchanged,
        'modified': modified,
        'added': added,
        'removed': removed,
        'total': max(len(main_lines), len(feat_lines))
    }


def compare_files(feat_path, main_path):
    """
    Compare two files and return differences
    """
    feat_lines = read_csv_file(feat_path)
    main_lines = read_csv_file(main_path)
    
    # Create line-by-line comparison
    comparison = []
    max_lines = max(len(feat_lines), len(main_lines))
    
    for i in range(max_lines):
        feat_line = feat_lines[i] if i < len(feat_lines) else None
        main_line = main_lines[i] if i < len(main_lines) else None
        
        if feat_line == main_line:
            status = 'same'
        elif feat_line is None:
            status = 'removed'
        elif main_line is None:
            status = 'added'
        else:
            status = 'modified'
        
        # Parse cell-level differences for modified rows
        cell_diffs = []
        if status == 'modified' and feat_line and main_line:
            feat_parts = feat_line.split(',')
            main_parts = main_line.split(',')
            max_parts = max(len(feat_parts), len(main_parts))
            
            for j in range(max_parts):
                feat_cell = feat_parts[j] if j < len(feat_parts) else ''
                main_cell = main_parts[j] if j < len(main_parts) else ''
                cell_diffs.append({
                    'feat': feat_cell,
                    'main': main_cell,
                    'different': feat_cell != main_cell
                })
        
        comparison.append({
            'line_num': i + 1,
            'feat': feat_line,
            'main': main_line,
            'status': status,
            'cell_diffs': cell_diffs
        })
    
    # Calculate statistics
    stats = {
        'total_lines': max_lines,
        'same': sum(1 for c in comparison if c['status'] == 'same'),
        'modified': sum(1 for c in comparison if c['status'] == 'modified'),
        'added': sum(1 for c in comparison if c['status'] == 'added'),
        'removed': sum(1 for c in comparison if c['status'] == 'removed')
    }
    
    return {
        'comparison': comparison,
        'stats': stats
    }


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check credentials
        if username in USERS and check_password_hash(USERS[username], password):
            session['logged_in'] = True
            session['username'] = username
            
            return redirect(url_for('index'))
        else:
            return redirect(url_for('login', error='1'))
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    """Dashboard landing page"""
    return render_template('dashboard.html', username=session.get('username'))


@app.route('/compare')
@login_required
def compare_view():
    """Comparison interface"""
    return render_template('index.html', username=session.get('username'))


@app.route('/api/structure')
@login_required
def get_structure():
    """Get scroll directory structure"""
    # Check if ARTIFACTS_DIR exists and has content
    if not ARTIFACTS_DIR.exists() or not any(ARTIFACTS_DIR.iterdir()):
        return jsonify({})
    
    structure = get_artifact_structure(ARTIFACTS_DIR)
    return jsonify(structure)


@app.route('/api/compare')
@login_required
def compare():
    """Compare two files and return full contents for Monaco Editor"""
    folder = request.args.get('folder')
    file_id = request.args.get('file')
    
    if not folder or not file_id:
        return jsonify({'error': 'Missing parameters'}), 400
    
    # Try normalized format first (feat-FILE, main-FILE), then fallback to legacy (FILE-feat, FILE-main)
    feat_path = ARTIFACTS_DIR / folder / f"feat-{file_id}"
    main_path = ARTIFACTS_DIR / folder / f"main-{file_id}"
    
    # Fallback to legacy format if normalized doesn't exist
    if not feat_path.exists():
        feat_path = ARTIFACTS_DIR / folder / f"{file_id}-feat"
    if not main_path.exists():
        main_path = ARTIFACTS_DIR / folder / f"{file_id}-main"
    
    if not feat_path.exists() or not main_path.exists():
        print(f"❌ Files not found for {folder}/{file_id}", flush=True)
        print(f"   Tried: {feat_path}", flush=True)
        print(f"   Tried: {main_path}", flush=True)
        return jsonify({'error': 'Files not found'}), 404
    
    # Read full file contents
    try:
        with open(main_path, 'r', encoding='utf-8') as f:
            main_content = f.read()
        with open(feat_path, 'r', encoding='utf-8') as f:
            feat_content = f.read()
    except Exception as e:
        return jsonify({'error': f'Error reading files: {str(e)}'}), 500
    
    # Calculate statistics using intelligent diff algorithm
    stats = calculate_diff_stats(main_content, feat_content)
    
    return jsonify({
        'folder_id': folder,
        'file_id': file_id,
        'main_content': main_content,
        'feat_content': feat_content,
        'stats': stats
    })


@app.route('/api/upload', methods=['POST'])
@login_required
def upload_artifact():
    """Upload and extract scroll bundle zip file"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not file.filename.endswith('.zip'):
        return jsonify({'error': 'Only ZIP files are allowed'}), 400
    
    try:
        print(f"\n📤 Upload received: {file.filename}", flush=True)
        
        # Save uploaded file
        zip_path = UPLOAD_FOLDER / file.filename
        file.save(zip_path)
        print(f"✅ File saved: {zip_path}", flush=True)
        
        # Extract to artifacts directory
        extract_to = UPLOAD_FOLDER / 'extracted'
        # Clear previous extraction
        if extract_to.exists():
            print(f"🧹 Clearing previous extraction...", flush=True)
            shutil.rmtree(extract_to)
        extract_to.mkdir(exist_ok=True)
        
        print(f"📦 Starting extraction...", flush=True)
        extract_artifact(zip_path, extract_to)
        
        # Update global artifacts directory (for this session)
        global ARTIFACTS_DIR
        ARTIFACTS_DIR = extract_to
        print(f"✅ ARTIFACTS_DIR updated to: {ARTIFACTS_DIR}", flush=True)
        
        # Get structure to return
        print(f"🔍 Getting artifact structure...", flush=True)
        structure = get_artifact_structure(ARTIFACTS_DIR)
        print(f"✅ Found {len(structure)} tenant(s)", flush=True)
        
        # Clean up uploaded ZIP file
        try:
            zip_path.unlink()
            print(f"🧹 Cleaned up: {zip_path}", flush=True)
        except:
            pass
        
        response_data = {
            'success': True,
            'message': 'Scroll uploaded and extracted successfully',
            'artifact_count': len(structure),
            'structure': structure
        }
        print(f"📨 Sending response: {len(str(response_data))} bytes\n", flush=True)
        
        return jsonify(response_data)
        
    except Exception as e:
        import traceback
        error_msg = f"Upload error: {str(e)}"
        print(f"❌ {error_msg}", flush=True)
        traceback.print_exc()
        return jsonify({'error': error_msg}), 500


@app.route('/api/download-zip/<filename>')
def download_zip(filename):
    """
    Download ZIP file from linear_attachments folder
    Note: No login required - this endpoint is used by Linear attachments
    Files are accessed via specific filenames only (tenant-chart-id.zip)
    """
    try:
        # Security: Only allow downloading from linear_attachments directory
        # and prevent directory traversal attacks
        if '..' in filename or '/' in filename:
            return jsonify({'error': 'Invalid filename'}), 400
        
        zip_path = LINEAR_ATTACHMENTS_DIR / filename
        
        # Log the request for debugging
        print(f"📥 ZIP download requested: {filename}", flush=True)
        print(f"   Looking in: {LINEAR_ATTACHMENTS_DIR}", flush=True)
        print(f"   Full path: {zip_path}", flush=True)
        print(f"   Exists: {zip_path.exists()}", flush=True)
        
        if not zip_path.exists():
            # List available files for debugging
            available_files = list(LINEAR_ATTACHMENTS_DIR.glob('*.zip'))
            print(f"   Available ZIP files: {[f.name for f in available_files]}", flush=True)
            return jsonify({'error': 'ZIP file not found'}), 404
        
        print(f"   ✅ Sending file: {zip_path.name}", flush=True)
        return send_file(
            zip_path,
            mimetype='application/zip',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        print(f"   ❌ Error downloading ZIP: {str(e)}", flush=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/use-sample')
@login_required
def use_sample():
    """Use the sample scroll directory (development only)"""
    global ARTIFACTS_DIR
    
    # SAMPLE_SCROLLS_PATH must be set via environment variable
    sample_path_str = os.getenv('SAMPLE_SCROLLS_PATH')
    if not sample_path_str:
        return jsonify({
            'success': False,
            'error': 'SAMPLE_SCROLLS_PATH not configured',
            'message': 'Set SAMPLE_SCROLLS_PATH environment variable to use sample scrolls',
            'hint': 'This endpoint is for development only. Upload scrolls via the dashboard in production.'
        }), 400
    
    sample_path = Path(sample_path_str)
    
    # Verify the path exists before using it
    if not sample_path.exists():
        return jsonify({
            'success': False,
            'error': 'Sample scrolls directory not found',
            'message': f'Path does not exist: {sample_path}',
            'hint': 'Set SAMPLE_SCROLLS_PATH environment variable or upload scrolls via the dashboard'
        }), 404
    
    ARTIFACTS_DIR = sample_path
    structure = get_artifact_structure(ARTIFACTS_DIR)
    
    return jsonify({
        'success': True,
        'message': f'Using sample scroll directory: {sample_path}',
        'artifact_count': len(structure),
        'structure': structure
    })


@app.route('/health')
def health_check():
    """Health check endpoint for monitoring and keep-alive"""
    return jsonify({
        'status': 'healthy',
        'service': 'WizardView',
        'version': '1.0'
    }), 200


@app.route('/static/<path:filename>')
def serve_static(filename):
    """Serve static files"""
    static_dir = Path(__file__).parent / 'static'
    return send_from_directory(static_dir, filename)


# Linear API Integration

# Cache for team UUID
_team_uuid_cache = {}

def linear_graphql_request(query, variables=None):
    """Make a GraphQL request to Linear API"""
    if not LINEAR_API_KEY:
        return {'error': 'Linear API key not configured'}
    
    headers = {
        'Authorization': LINEAR_API_KEY,
        'Content-Type': 'application/json'
    }
    
    payload = {'query': query}
    if variables:
        payload['variables'] = variables
    
    try:
        response = requests.post(LINEAR_API_URL, json=payload, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        # Get the actual error response from Linear
        error_detail = {'error': str(e)}
        try:
            error_body = response.json()
            error_detail['response'] = error_body
            print(f"❌ Linear API Error: {error_body}", flush=True)
        except:
            error_detail['response'] = response.text
            print(f"❌ Linear API Error (raw): {response.text}", flush=True)
        return error_detail
    except requests.exceptions.RequestException as e:
        print(f"❌ Request Exception: {str(e)}", flush=True)
        return {'error': str(e)}


def get_team_uuid(team_key):
    """Get the UUID for a team given its key (e.g., 'ENG')"""
    # Check cache first
    if team_key in _team_uuid_cache:
        return _team_uuid_cache[team_key]
    
    query = """
    query Teams {
        teams {
            nodes {
                id
                key
                name
            }
        }
    }
    """
    
    result = linear_graphql_request(query)
    
    if 'errors' in result or 'error' in result:
        print(f"Error fetching teams: {result}")
        return None
    
    try:
        teams = result['data']['teams']['nodes']
        for team in teams:
            _team_uuid_cache[team['key']] = team['id']
            if team['key'] == team_key:
                print(f"Found team UUID for '{team_key}': {team['id']}")
                return team['id']
    except (KeyError, TypeError) as e:
        print(f"Error parsing teams: {e}")
        return None
    
    return None


@app.route('/api/linear/team-members')
@login_required
def get_linear_team_members():
    """Get team members from Linear"""
    if not LINEAR_API_KEY:
        return jsonify({
            'success': False,
            'error': 'Linear API key not configured. Please set LINEAR_API_KEY environment variable.'
        }), 400
    
    # Get team UUID from key
    team_uuid = get_team_uuid(LINEAR_TEAM_ID)
    if not team_uuid:
        return jsonify({
            'success': False,
            'error': f'Could not find team with key: {LINEAR_TEAM_ID}'
        }), 404
    
    # GraphQL query to get team members (with team info for verification)
    query = """
    query TeamMembers($teamId: String!) {
        team(id: $teamId) {
            key
            name
            members {
                nodes {
                    id
                    name
                    displayName
                    email
                    active
                }
            }
        }
    }
    """
    
    variables = {'teamId': team_uuid}
    
    print(f"Fetching team members for team UUID: {team_uuid} (key: {LINEAR_TEAM_ID})")
    
    result = linear_graphql_request(query, variables)
    
    if 'error' in result:
        return jsonify({'success': False, 'error': result['error']}), 500
    
    if 'errors' in result:
        return jsonify({'success': False, 'error': result['errors'][0]['message']}), 500
    
    try:
        team_data = result['data']['team']
        team_key = team_data.get('key', '')
        team_name = team_data.get('name', '')
        members = team_data['members']['nodes']
        
        print(f"Found {len(members)} members in team '{team_name}' (key: {team_key})")
        
        # Filter active members only from the ENG team
        # Use displayName (nickname) if available, otherwise fall back to full name
        active_members = [
            {
                'id': m['id'], 
                'name': m.get('displayName') or m['name'],  # Prefer displayName (nickname)
                'email': m.get('email', '')
            }
            for m in members if m.get('active', True)
        ]
        
        print(f"Returning {len(active_members)} active members from ENG team")
        for member in active_members:
            print(f"  - {member['name']} ({member['email']})")
        
        return jsonify({'success': True, 'members': active_members, 'team': team_key})
    except (KeyError, TypeError) as e:
        print(f"Error parsing team members: {e}")
        return jsonify({'success': False, 'error': f'Failed to parse team members: {str(e)}'}), 500


@app.route('/api/linear/create-issue', methods=['POST'])
@login_required
def create_linear_issue():
    """Create a Linear issue with HTML attachment"""
    if not LINEAR_API_KEY:
        return jsonify({
            'success': False,
            'error': 'Linear API key not configured. Please set LINEAR_API_KEY environment variable.'
        }), 400
    
    # Get team UUID from key
    team_uuid = get_team_uuid(LINEAR_TEAM_ID)
    if not team_uuid:
        return jsonify({
            'success': False,
            'error': f'Could not find team with key: {LINEAR_TEAM_ID}'
        }), 404
    
    data = request.json
    folder_id = data.get('folderId')
    file_id = data.get('fileId')
    assignee_id = data.get('assigneeId')
    stats = data.get('stats', {})
    attach_zip = data.get('attachZip', True)  # Default to True for backward compatibility
    
    if not all([folder_id, file_id, assignee_id]):
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    
    print(f"\n{'='*60}", flush=True)
    print(f"📝 Creating Linear issue with attachZip={attach_zip}", flush=True)
    print(f"   Folder: {folder_id}, File: {file_id}", flush=True)
    print(f"{'='*60}\n", flush=True)
    
    # Create issue title
    title = f"Gandalf's WizardView Report for {folder_id}-{file_id}"
    
    # Get app URL (use Render deployment URL or environment variable)
    app_url = os.environ.get('WIZARDVIEW_URL', 'https://wizardview.onrender.com')
    
    # Create issue description with app link
    description = f"""📊 Regression Diff Report

**File**: {file_id}
**Tenant**: {folder_id}

**Statistics**:
✅ Added: {stats.get('added', 0)}
❌ Removed: {stats.get('removed', 0)}
⚠️ Modified: {stats.get('modified', 0)}
⚪ Unchanged: {stats.get('unchanged', 0)}

**Total Changes**: {stats.get('added', 0) + stats.get('removed', 0) + stats.get('modified', 0)} items affected

---
📦 **Attached ZIP**: Contains main and feat files for this specific chart/model
🔗 **View in WizardView**: Upload the attached ZIP at [{app_url}]({app_url}) to compare interactively
"""
    
    # Step 1: Create ZIP file with only the specific chart/model files (if requested)
    zip_file_data = None
    if attach_zip:
        try:
            tenant_path = os.path.join(ARTIFACTS_DIR, folder_id)
            
            print(f"🔍 Checking tenant path: {tenant_path}", flush=True)
            print(f"🔍 ARTIFACTS_DIR: {ARTIFACTS_DIR}", flush=True)
            print(f"🔍 Folder ID: {folder_id}", flush=True)
            print(f"🔍 File ID: {file_id}", flush=True)
            
            if not os.path.exists(tenant_path):
                print(f"❌ Tenant folder not found: {tenant_path}", flush=True)
            else:
                print(f"✅ Tenant folder exists: {tenant_path}", flush=True)
                print(f"📦 Creating ZIP for {file_id} from tenant {folder_id}", flush=True)
                
                # After normalization, all files are in Format 2: tenant/main-FILE and tenant/feat-FILE
                # But we keep legacy patterns for backwards compatibility
                main_patterns = [
                    os.path.join(tenant_path, f"main-{file_id}"),      # Normalized format (preferred)
                    os.path.join(tenant_path, 'main', f"{file_id}.csv"),  # Legacy format
                    os.path.join(tenant_path, f"{file_id}-main"),      # Alternative naming
                ]
                feat_patterns = [
                    os.path.join(tenant_path, f"feat-{file_id}"),      # Normalized format (preferred)
                    os.path.join(tenant_path, 'feat', f"{file_id}.csv"),  # Legacy format
                    os.path.join(tenant_path, f"{file_id}-feat"),      # Alternative naming
                ]
                
                # Check if files exist
                files_to_add = []
                
                # Find main file
                main_file = None
                for pattern in main_patterns:
                    if os.path.exists(pattern):
                        main_file = pattern
                        files_to_add.append(('main', main_file))
                        print(f"  ✅ Found main file: {main_file}", flush=True)
                        break
                if not main_file:
                    print(f"  ⚠️ Main file not found. Tried: {main_patterns}", flush=True)
                
                # Find feat file
                feat_file = None
                for pattern in feat_patterns:
                    if os.path.exists(pattern):
                        feat_file = pattern
                        files_to_add.append(('feat', feat_file))
                        print(f"  ✅ Found feat file: {feat_file}", flush=True)
                        break
                if not feat_file:
                    print(f"  ⚠️ Feat file not found. Tried: {feat_patterns}", flush=True)
                
                if files_to_add:
                    # Save ZIP file to disk in linear_attachments folder
                    filename = f"{folder_id}-{file_id}.zip"
                    zip_filepath = LINEAR_ATTACHMENTS_DIR / filename
                    
                    print(f"  Creating ZIP file: {zip_filepath}", flush=True)
                    
                    with zipfile.ZipFile(zip_filepath, 'w', zipfile.ZIP_DEFLATED) as zipf:
                        # Add only the specific main and feat files
                        for branch, file_path in files_to_add:
                            # Use structure: tenant_folder/filename-branch (no extension, matching the original format)
                            arcname = f"{folder_id}/{file_id}-{branch}"
                            zipf.write(file_path, arcname)
                            print(f"  ✅ Added to ZIP: {arcname}", flush=True)
                    
                    # Get the file size
                    file_size = zip_filepath.stat().st_size
                    
                    print(f"✅ ZIP file saved: {zip_filepath} ({file_size} bytes)", flush=True)
                    
                    zip_file_data = {
                        'filename': filename,
                        'filepath': str(zip_filepath),
                        'size': file_size
                    }
                else:
                    print(f"❌ No files found to add to ZIP for {file_id}", flush=True)
        except Exception as e:
            print(f"❌ Failed to create ZIP file: {str(e)}", flush=True)
            import traceback
            traceback.print_exc()
    else:
        print(f"ℹ️ ZIP attachment disabled by user toggle", flush=True)
    
    # Check if ZIP was created
    if zip_file_data:
        print(f"✅ ZIP file data ready: {zip_file_data['filename']} ({zip_file_data['size']} bytes)", flush=True)
    else:
        print(f"⚠️ No ZIP file data created!", flush=True)
    
    # Step 2: Get the current cycle
    cycle_query = """
    query ActiveCycle($teamId: String!) {
        team(id: $teamId) {
            activeCycle {
                id
                name
            }
        }
    }
    """
    
    cycle_result = linear_graphql_request(cycle_query, {'teamId': team_uuid})
    cycle_id = None
    
    if 'errors' not in cycle_result and 'data' in cycle_result:
        try:
            cycle_id = cycle_result['data']['team']['activeCycle']['id']
        except (KeyError, TypeError):
            pass  # No active cycle
    
    # Step 3: Create the issue
    create_query = """
    mutation IssueCreate($input: IssueCreateInput!) {
        issueCreate(input: $input) {
            success
            issue {
                id
                identifier
                url
            }
        }
    }
    """
    
    # Build issue input (without null values)
    issue_input = {
        'teamId': team_uuid,
        'title': title,
        'description': description,
        'assigneeId': assignee_id,
    }
    
    # Get the "Todo" state ID for the team
    state_query = """
    query TeamStates($teamId: String!) {
        team(id: $teamId) {
            states {
                nodes {
                    id
                    name
                    type
                }
            }
        }
    }
    """
    
    state_result = linear_graphql_request(state_query, {'teamId': team_uuid})
    
    if 'errors' not in state_result and 'data' in state_result:
        try:
            states = state_result['data']['team']['states']['nodes']
            # Find "Todo" state specifically (prioritize Todo over Backlog)
            todo_state = None
            backlog_state = None
            
            for state in states:
                state_name_lower = state['name'].lower()
                if state_name_lower == 'todo':
                    todo_state = state['id']
                    break  # Found Todo, use it immediately
                elif state_name_lower == 'backlog' and not todo_state:
                    backlog_state = state['id']
                elif state['type'] == 'unstarted' and not todo_state and not backlog_state:
                    backlog_state = state['id']
            
            # Prioritize Todo, then Backlog, then any unstarted state
            if todo_state:
                issue_input['stateId'] = todo_state
                print(f"Using Todo state: {todo_state}")
            elif backlog_state:
                issue_input['stateId'] = backlog_state
                print(f"Using Backlog/Unstarted state: {backlog_state}")
        except (KeyError, TypeError) as e:
            print(f"Error finding state: {e}")
            pass  # Will use default state
    
    # Add cycle if available (automatically assign to current cycle)
    if cycle_id:
        issue_input['cycleId'] = cycle_id
        print(f"Assigned to current cycle: {cycle_id}")
    
    # Set priority to High (2 = High in Linear)
    # Linear priority values: 0 = No priority, 1 = Urgent, 2 = High, 3 = Medium, 4 = Low
    issue_input['priority'] = 2
    print(f"Set priority to High (2)")
    
    # Debug log
    print(f"Creating Linear issue with input: {issue_input}")
    
    create_result = linear_graphql_request(create_query, {'input': issue_input})
    
    # Debug log
    print(f"Linear API response: {create_result}")
    
    if 'error' in create_result:
        return jsonify({'success': False, 'error': create_result['error']}), 500
    
    if 'errors' in create_result:
        error_msg = create_result['errors'][0]['message']
        print(f"Linear API error: {error_msg}")
        # Include more details in the error
        error_details = create_result['errors'][0].get('extensions', {})
        if error_details:
            error_msg += f" - Details: {error_details}"
        return jsonify({'success': False, 'error': error_msg}), 500
    
    try:
        issue_data = create_result['data']['issueCreate']
        if issue_data['success']:
            issue_id = issue_data['issue']['id']
            issue_identifier = issue_data['issue']['identifier']
            issue_url = issue_data['issue']['url']
            
            print(f"✅ Issue created: {issue_identifier}", flush=True)
            print(f"   Issue ID: {issue_id}", flush=True)
            print(f"   Issue URL: {issue_url}", flush=True)
            
            # Step 4: Update issue description with ZIP file information
            print(f"\n🔍 Checking if zip_file_data exists: {zip_file_data is not None}", flush=True)
            if zip_file_data:
                print(f"✅ ZIP file data found: {zip_file_data['filename']} ({zip_file_data['size']} bytes)", flush=True)
                print(f"✅ ZIP file saved at: {zip_file_data['filepath']}", flush=True)
                try:
                    # Create attachment URL for the ZIP file
                    zip_download_url = f"{app_url}/api/download-zip/{zip_file_data['filename']}"
                    print(f"   Creating attachment with URL: {zip_download_url}", flush=True)
                    
                    # Create attachment in Linear using attachmentLinkURL
                    attachment_query = """
                    mutation AttachmentLinkURL($issueId: String!, $url: String!, $title: String) {
                        attachmentLinkURL(issueId: $issueId, url: $url, title: $title) {
                            success
                            lastSyncId
                        }
                    }
                    """
                    
                    attachment_vars = {
                        'issueId': issue_id,
                        'url': zip_download_url,
                        'title': f"📦 {zip_file_data['filename']}"
                    }
                    
                    attachment_result = linear_graphql_request(attachment_query, attachment_vars)
                    
                    if 'errors' in attachment_result:
                        print(f"   ❌ Failed to create attachment: {attachment_result['errors']}", flush=True)
                        attachment_created = False
                    elif attachment_result.get('data', {}).get('attachmentLinkURL', {}).get('success'):
                        print(f"   ✅ Attachment created successfully!", flush=True)
                        attachment_created = True
                    else:
                        print(f"   ⚠️ Unexpected attachment response: {attachment_result}", flush=True)
                        attachment_created = False
                    
                    # Determine if it's a chart or model intelligently
                    if file_id.upper().startswith('CHART-'):
                        resource_type = 'chart'
                    elif file_id.upper().startswith('MODEL-'):
                        resource_type = 'model'
                    else:
                        resource_type = 'chart/model'
                    
                    # Build attachment info message
                    attachment_info = ""
                    if attachment_created:
                        attachment_info = f"\n📦 **Auto-attached**: `{zip_file_data['filename']}` (main + feat files)\n"
                    
                    # Update issue description
                    updated_description = f"""📊 Regression Diff Report

**File**: {file_id}
**Tenant**: {folder_id}

**Statistics**:
✅ Added: {stats.get('added', 0)}
❌ Removed: {stats.get('removed', 0)}
⚠️ Modified: {stats.get('modified', 0)}
⚪ Unchanged: {stats.get('unchanged', 0)}

**Total Changes**: {stats.get('added', 0) + stats.get('removed', 0) + stats.get('modified', 0)} items affected
{attachment_info}
---
📜 **Scroll Files**: Download the attached ZIP file from Resources that contains main and feat files for this {resource_type}.

🔗 **Interactive Comparison**: Upload the ZIP file at [{app_url}]({app_url}) to view the full side-by-side diff in WizardView.
"""
                    
                    update_query = """
                    mutation IssueUpdate($id: String!, $input: IssueUpdateInput!) {
                        issueUpdate(id: $id, input: $input) {
                            success
                            issue {
                                id
                            }
                        }
                    }
                    """
                    
                    update_vars = {
                        'id': issue_id,
                        'input': {
                            'description': updated_description
                        }
                    }
                    
                    update_result = linear_graphql_request(update_query, update_vars)
                    
                    if 'errors' in update_result:
                        print(f"   ❌ Failed to update issue description: {update_result['errors']}", flush=True)
                    elif update_result.get('data', {}).get('issueUpdate', {}).get('success'):
                        print(f"   ✅ Issue description updated!", flush=True)
                        print(f"\n{'='*60}", flush=True)
                        print(f"🎉 SUCCESS! Linear issue {issue_identifier} created with attachment!", flush=True)
                        print(f"   📎 ZIP File: {zip_file_data['filename']}", flush=True)
                        print(f"   📁 Location: {zip_file_data['filepath']}", flush=True)
                        print(f"   🔗 Download URL: {zip_download_url}", flush=True)
                        print(f"{'='*60}\n", flush=True)
                    else:
                        print(f"   ⚠️ Unexpected update response: {update_result}", flush=True)
                        
                except Exception as e:
                    print(f"❌ Failed to update issue description: {str(e)}", flush=True)
                    import traceback
                    traceback.print_exc()
                    # Continue anyway, issue was created successfully
            else:
                print(f"⚠️ No ZIP file data available - scroll files not found in artifacts directory", flush=True)
                print(f"   Expected path: {ARTIFACTS_DIR}/{folder_id}/main/{file_id}.csv", flush=True)
                print(f"   Expected path: {ARTIFACTS_DIR}/{folder_id}/feat/{file_id}.csv", flush=True)
                print(f"   Please upload scrolls first from the dashboard at http://localhost:5001/", flush=True)
            
            return jsonify({
                'success': True,
                'issueId': issue_id,
                'issueIdentifier': issue_identifier,
                'issueUrl': issue_url
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to create issue'}), 500
    except (KeyError, TypeError) as e:
        return jsonify({'success': False, 'error': f'Failed to parse issue response: {str(e)}'}), 500


def validate_production_config():
    """Validate configuration for production deployment"""
    issues = []
    warnings = []
    
    # Check critical environment variables
    if not os.getenv('SECRET_KEY'):
        warnings.append("SECRET_KEY not set - using insecure development key")
    
    if not LINEAR_API_KEY:
        warnings.append("LINEAR_API_KEY not set - Linear integration will not work")
    
    if not os.getenv('WIZARDVIEW_URL'):
        warnings.append("WIZARDVIEW_URL not set - using default URL for Linear links")
    
    # Check if using default credentials
    if os.getenv('AUTH_USERNAME') == 'sdet-team@drivetrain.ai' or not os.getenv('AUTH_USERNAME'):
        warnings.append("Using default AUTH_USERNAME - change in production!")
    
    if os.getenv('AUTH_PASSWORD') == 'OneRing2RuleThemAll' or not os.getenv('AUTH_PASSWORD'):
        warnings.append("Using default AUTH_PASSWORD - change in production!")
    
    # Print validation results
    if warnings:
        print("\n⚠️  PRODUCTION CONFIGURATION WARNINGS:", flush=True)
        for warning in warnings:
            print(f"   • {warning}", flush=True)
        print("", flush=True)
    
    if issues:
        print("\n❌ CRITICAL CONFIGURATION ISSUES:", flush=True)
        for issue in issues:
            print(f"   • {issue}", flush=True)
        print("\nApplication may not work correctly!\n", flush=True)
    
    return len(issues) == 0


# Run validation on import (works for both gunicorn and direct run)
validate_production_config()


if __name__ == '__main__':
    print("🧙‍♂️ Starting WizardView (Development Mode)...")
    print("   Gandalf's tool for regression clarity")
    print(f"   Using scrolls from: {ARTIFACTS_DIR}")
    print("   ⚠️  DEBUG MODE ENABLED - Do not use in production!")
    app.run(debug=True, port=5001, host='127.0.0.1')

