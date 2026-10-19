# Secure REST API with CI/CD Security Scanning

## Project Description

This is a secure REST API built with Flask, demonstrating secure coding practices and automated security scanning in a CI/CD pipeline.

### API Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/auth/register` | Register a new user | No |
| POST | `/auth/login` | Login and receive JWT token | No |
| GET | `/api/data` | Get current user's posts | Yes (JWT) |
| POST | `/api/posts` | Create a new post | Yes (JWT) |

---

## Security Measures Implemented

### 1. Protection against SQL Injection

**Implementation**: Using Flask-SQLAlchemy ORM with parameterized queries. All database queries use ORM methods (e.g., `User.query.filter_by(username=username)`) which automatically escape user input. No string concatenation is used to build SQL queries.

```python
# Example: parameterized query via ORM
user = User.query.filter_by(username=username).first()
```

### 2. Protection against XSS (Cross-Site Scripting)

**Implementation**: All user-generated content returned in API responses is HTML-escaped using a custom `escape_html()` function that converts special characters (`&`, `<`, `>`, `"`, `'`) to their HTML entity equivalents.

```python
def escape_html(text):
    return (text.replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))
```

### 3. Protection against Broken Authentication

**Implementation**:
- **Password hashing**: Passwords are hashed using bcrypt with a salt (never stored in plaintext)
- **JWT tokens**: Upon successful login, a JWT token is issued with a 1-hour expiration
- **Token verification middleware**: All protected endpoints verify the JWT token before processing requests

```python
# Password hashing
bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# JWT generation
jwt.encode(payload, SECRET_KEY, algorithm='HS256')

# JWT verification middleware
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        data = jwt.verify(token, SECRET_KEY)
        ...
```

---

## CI/CD Security Pipeline

GitHub Actions runs on every push and pull request:

- **SAST (Static Application Security Testing)**: Bandit — scans Python source code for security issues
- **SCA (Software Composition Analysis)**: Safety — scans dependencies for known vulnerabilities

*[Screenshot: GitHub Actions successful run]*

---

## CVE Vulnerability Analysis

### Selected Vulnerability

*[To be filled after Vulhub setup: CVE-ID, description]*

### Reproduction Steps

*[To be filled: commands and screenshots]*

### Root Cause Analysis

*[To be filled: explanation of the vulnerability]*

### Fix Applied

*[To be filled: what was changed and why]*

### Fix Verification

*[To be filled: proof that the attack no longer works]*
