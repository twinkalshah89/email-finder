# from flask import Flask

# app = Flask(__name__)

# @app.route("/")
# def home():
#     return "Hello, Flask is working!"

# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=8080)



from flask import Flask, request, jsonify
from mailscout.scout import Scout  # Import Scout class
import time
from functools import wraps
import re
from typing import Dict, Any

app = Flask(__name__)
scout = Scout()  # Initialize Scout

# Rate limiting configuration
RATE_LIMIT = 100  # requests per minute
rate_limit_data: Dict[str, list] = {}

def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        current_time = time.time()
        
        # Clean old timestamps
        if ip in rate_limit_data:
            rate_limit_data[ip] = [t for t in rate_limit_data[ip] if current_time - t < 60]
        else:
            rate_limit_data[ip] = []
        
        # Check rate limit
        if len(rate_limit_data[ip]) >= RATE_LIMIT:
            return jsonify({
                "error": "Rate limit exceeded. Please try again later.",
                "retry_after": 60 - (current_time - rate_limit_data[ip][0])
            }), 429
        
        rate_limit_data[ip].append(current_time)
        return f(*args, **kwargs)
    return decorated_function

def validate_email(email: str) -> bool:
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_domain(domain: str) -> bool:
    """Validate domain format."""
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$'
    return bool(re.match(pattern, domain))

def validate_request_data(data: Dict[str, Any], required_fields: list) -> tuple[bool, str]:
    """Validate request data and return (is_valid, error_message)."""
    for field in required_fields:
        if field not in data:
            return False, f"Missing required field: {field}"
    return True, ""

@app.route("/")
def home():
    return jsonify({
        "status": "running",
        "version": "1.0.0",
        "endpoints": {
            "/verify": "POST - Verify a single email address",
            "/find": "POST - Find valid emails for a domain and names"
        }
    })

@app.route("/verify", methods=["POST"])
@rate_limit
def verify_email():
    data = request.get_json()
    is_valid, error = validate_request_data(data, ["email"])
    if not is_valid:
        return jsonify({"error": error}), 400

    email = data.get("email", "").strip().lower()
    if not validate_email(email):
        return jsonify({"error": "Invalid email format"}), 400

    try:
        is_valid = scout.check_smtp(email)
        return jsonify({
            "email": email,
            "valid": is_valid,
            "timestamp": time.time()
        })
    except Exception as e:
        return jsonify({
            "error": "Email verification failed",
            "details": str(e)
        }), 500

# @app.route("/find", methods=["POST"])
# @rate_limit
# def find_emails():
#     try:
#         data = request.get_json()
#         if not data:
#             return jsonify({"error": "No JSON data provided"}), 400

#         domain = data.get("domain", "").strip().lower()
#         if not domain:
#             return jsonify({"error": "Domain is required"}), 400

#         names = data.get("names", [])
#         if not isinstance(names, list) or not names:
#             return jsonify({"error": "Names must be a non-empty list"}), 400

#         valid_emails = []
#         for name in names:
#             if not isinstance(name, str):
#                 continue

#             # Handle both space-separated and individual name parts
#             name_parts = name.strip().split()
#             if len(name_parts) > 1:
#                 # If name contains multiple parts (e.g., "Alex Bird")
#                 first_name = name_parts[0]
#                 last_name = name_parts[-1]
#             else:
#                 # If names are provided separately (e.g., ["Alex", "Bird"])
#                 first_name = name
#                 last_name = names[names.index(name) + 1] if names.index(name) + 1 < len(names) else ""
#                 if last_name in names:  # Skip the next name since we used it as last name
#                     continue

#             # Find valid emails for this name combination
#             emails = scout.find_valid_emails(
#                 first_name=first_name,
#                 last_name=last_name,
#                 domain=domain
#             )
#             valid_emails.extend(emails)

#         # Remove duplicates while preserving order
#         valid_emails = list(dict.fromkeys(valid_emails))

#         return jsonify({
#             "domain": domain,
#             "names": names,
#             "valid_emails": valid_emails,
#             "count": len(valid_emails),
#             "timestamp": time.time()
#         })

#     except Exception as e:
#         print(f"Error in find_emails: {str(e)}")
#         return jsonify({
#             "error": "Email finding failed",
#             "details": str(e)
#         }), 500

@app.route("/find", methods=["POST"])
@rate_limit
def find_emails():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        domain = data.get("domain", "").strip().lower()
        if not domain:
            return jsonify({"error": "Domain is required"}), 400

        names = data.get("names", [])
        if not isinstance(names, list) or not names:
            return jsonify({"error": "Names must be a non-empty list"}), 400

        # Call Scout with the names list directly
        result = scout.find_valid_emails(domain=domain, names=names)

        return jsonify(result)

    except Exception as e:
        print(f"Error in find_emails: {str(e)}")
        return jsonify({
            "error": "Email finding failed",
            "details": str(e)
        }), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
