from flask import Flask, jsonify, request
import subprocess
import json
import os
import threading
import tempfile
from pathlib import Path
from functools import wraps
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration - Render compatible
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BLACKBIRD_PATH = os.path.join(BASE_DIR, "blackbird")
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

# CORS decorator
def cors(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = f(*args, **kwargs)
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        return response
    return decorated_function

@app.route('/')
@cors
def home():
    return jsonify({
        "message": "Blackbird OSINT API",
        "version": "1.0",
        "status": "Active",
        "endpoints": {
            "/scan/username": "POST - Scan a username across platforms",
            "/scan/email": "POST - Scan an email across platforms",
            "/results/<scan_id>": "GET - Get scan results",
            "/status": "GET - API status",
            "/platforms": "GET - List supported platforms"
        },
        "documentation": "https://github.com/p1ngul1n0/blackbird"
    })

@app.route('/status')
@cors
def status():
    """Check if Blackbird is available"""
    try:
        # Check if blackbird binary exists
        if not os.path.exists(BLACKBIRD_PATH):
            return jsonify({
                "status": "error",
                "message": "Blackbird binary not found. Build required.",
                "solution": "Run 'go build -o blackbird' in repository root"
            }), 500
            
        # Test blackbird with help command
        result = subprocess.run([BLACKBIRD_PATH, "--help"], 
                              capture_output=True, text=True, timeout=10)
        
        return jsonify({
            "status": "online",
            "blackbird_available": result.returncode == 0,
            "blackbird_version": get_blackbird_version(),
            "message": "API is running. Use /scan/username or /scan/email to start scans."
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Status check failed: {str(e)}"
        }), 500

@app.route('/scan/username', methods=['POST'])
@cors
def scan_username():
    """Scan a username across all platforms"""
    try:
        data = request.get_json()
        if not data or 'username' not in data:
            return jsonify({"error": "Username is required"}), 400
        
        username = data['username']
        scan_id = f"username_{username}_{os.urandom(4).hex()}"
        output_file = os.path.join(DATA_DIR, f"{scan_id}.json")
        
        # Check if blackbird exists
        if not os.path.exists(BLACKBIRD_PATH):
            return jsonify({
                "error": "Blackbird not built",
                "message": "Blackbird binary needs to be compiled first",
                "solution": "Run 'go build -o blackbird' in the repository root"
            }), 500
        
        # Run scan in background thread
        thread = threading.Thread(
            target=run_blackbird_username_scan,
            args=(username, output_file, scan_id)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            "message": "Scan started",
            "scan_id": scan_id,
            "username": username,
            "results_url": f"/results/{scan_id}",
            "note": "Results will be available in 1-5 minutes"
        }), 202
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/scan/email', methods=['POST'])
@cors
def scan_email():
    """Scan an email across all platforms"""
    try:
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({"error": "Email is required"}), 400
        
        email = data['email']
        scan_id = f"email_{email}_{os.urandom(4).hex()}"
        output_file = os.path.join(DATA_DIR, f"{scan_id}.json")
        
        # Check if blackbird exists
        if not os.path.exists(BLACKBIRD_PATH):
            return jsonify({
                "error": "Blackbird not built",
                "message": "Blackbird binary needs to be compiled first",
                "solution": "Run 'go build -o blackbird' in the repository root"
            }), 500
        
        # Run scan in background thread
        thread = threading.Thread(
            target=run_blackbird_email_scan,
            args=(email, output_file, scan_id)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            "message": "Scan started",
            "scan_id": scan_id,
            "email": email,
            "results_url": f"/results/{scan_id}",
            "note": "Results will be available in 1-5 minutes"
        }), 202
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/results/<scan_id>')
@cors
def get_results(scan_id):
    """Get scan results by ID"""
    try:
        # Security check - prevent path traversal
        if '..' in scan_id or '/' in scan_id:
            return jsonify({"error": "Invalid scan ID"}), 400
            
        result_file = os.path.join(DATA_DIR, f"{scan_id}.json")
        
        if not os.path.exists(result_file):
            return jsonify({
                "status": "processing",
                "message": "Scan still in progress",
                "scan_id": scan_id
            }), 202
        
        with open(result_file, 'r') as f:
            results = json.load(f)
        
        return jsonify({
            "status": "completed",
            "scan_id": scan_id,
            "results": results
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/platforms')
@cors
def get_platforms():
    """Get list of supported platforms"""
    try:
        if not os.path.exists(BLACKBIRD_PATH):
            return jsonify({
                "error": "Blackbird not built",
                "message": "Compile blackbird first to see supported platforms"
            }), 500
            
        result = subprocess.run([BLACKBIRD_PATH, "--list-platforms"], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            platforms = result.stdout.strip().split('\n')
            return jsonify({
                "platforms": platforms,
                "count": len(platforms)
            })
        else:
            return jsonify({
                "platforms": ["Unknown - compile blackbird to see list"],
                "count": 0
            })
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def run_blackbird_username_scan(username, output_file, scan_id):
    """Run Blackbird username scan and save results"""
    try:
        logger.info(f"Starting scan for username: {username}")
        
        # Run Blackbird command
        cmd = [
            BLACKBIRD_PATH,
            "-u", username,
            "--no-color"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        # Process results
        scan_result = {
            "username": username,
            "timestamp": str(os.path.getctime(output_file)) if os.path.exists(output_file) else "unknown",
            "command": " ".join(cmd),
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "status": "completed" if result.returncode == 0 else "failed"
        }
        
        # Save results
        with open(output_file, 'w') as f:
            json.dump(scan_result, f, indent=2)
            
        logger.info(f"Scan completed for username: {username}")
                
    except subprocess.TimeoutExpired:
        error_result = {
            "error": "Scan timed out after 5 minutes",
            "status": "timeout",
            "username": username
        }
        with open(output_file, 'w') as f:
            json.dump(error_result, f)
        logger.error(f"Scan timed out for username: {username}")
    except Exception as e:
        error_result = {
            "error": str(e),
            "status": "failed",
            "username": username
        }
        with open(output_file, 'w') as f:
            json.dump(error_result, f)
        logger.error(f"Scan failed for username: {username}: {str(e)}")

def run_blackbird_email_scan(email, output_file, scan_id):
    """Run Blackbird email scan and save results"""
    try:
        logger.info(f"Starting scan for email: {email}")
        
        # Run Blackbird command
        cmd = [
            BLACKBIRD_PATH,
            "-e", email,
            "--no-color"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        # Process results
        scan_result = {
            "email": email,
            "timestamp": str(os.path.getctime(output_file)) if os.path.exists(output_file) else "unknown",
            "command": " ".join(cmd),
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "status": "completed" if result.returncode == 0 else "failed"
        }
        
        # Save results
        with open(output_file, 'w') as f:
            json.dump(scan_result, f, indent=2)
            
        logger.info(f"Scan completed for email: {email}")
                
    except subprocess.TimeoutExpired:
        error_result = {
            "error": "Scan timed out after 5 minutes",
            "status": "timeout",
            "email": email
        }
        with open(output_file, 'w') as f:
            json.dump(error_result, f)
        logger.error(f"Scan timed out for email: {email}")
    except Exception as e:
        error_result = {
            "error": str(e),
            "status": "failed",
            "email": email
        }
        with open(output_file, 'w') as f:
            json.dump(error_result, f)
        logger.error(f"Scan failed for email: {email}: {str(e)}")

def get_blackbird_version():
    """Get Blackbird version"""
    try:
        if os.path.exists(BLACKBIRD_PATH):
            result = subprocess.run([BLACKBIRD_PATH, "--version"], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout.strip()
        return "Unknown (build required)"
    except:
        return "Unknown"

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"Starting Blackbird API on port {port}")
    print(f"Blackbird path: {BLACKBIRD_PATH}")
    print(f"Blackbird exists: {os.path.exists(BLACKBIRD_PATH)}")
    
    # Test if Blackbird is built
    if os.path.exists(BLACKBIRD_PATH):
        try:
            result = subprocess.run([BLACKBIRD_PATH, "--help"], 
                                  capture_output=True, text=True, timeout=5)
            print(f"Blackbird test: {'SUCCESS' if result.returncode == 0 else 'FAILED'}")
        except Exception as e:
            print(f"Blackbird test error: {e}")
    else:
        print("Warning: Blackbird binary not found. Build it with: go build -o blackbird")
    
    app.run(host='0.0.0.0', port=port)
