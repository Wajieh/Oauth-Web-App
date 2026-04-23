import httpx
import secrets
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
import os
app = FastAPI()

# --- CONFIGURATION (Replace with your actual Google Credentials) ---
CLIENT_ID = "CLIENT_ID"
CLIENT_SECRET = "CLIENT_SECRET"
REDIRECT_URI = os.getenv("http://localhost:8000/callback")
AUTH_URL = os.getenv("https://accounts.google.com/o/oauth2/v2/auth")
TOKEN_URL = "https://oauth2.googleapis.com/token"
SCOPES = "openid email profile"

# Global "Database" for learning (In production, use a secure session/DB)
db = {"state": None, "tokens": {}}

@app.get("/", response_class=HTMLResponse)
async def index():
    """Step 1: Simple Landing Page"""
    return """
    <html>
        <body>
            <h1>OAuth 2.0 From Scratch</h1>
            <a href="/login"><button style="padding:10px 20px;">Login with Google</button></a>
        </body>
    </html>
    """

@app.get("/login")
async def login():
    """Step 2: Construct Auth URL & Redirect"""
    state = secrets.token_urlsafe(32)
    db["state"] = state  # Store for verification
    
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": SCOPES,
        "state": state,
        "access_type": "offline",
        "prompt": "consent"
    }
    
    # Building the URL manually
    query_string = "&".join([f"{k}={v}" for k, v in params.items()])
    return RedirectResponse(f"{AUTH_URL}?{query_string}")

@app.get("/callback")
async def callback(request: Request):
    """Step 3: Capture Code and Exchange for Token"""
    code = request.query_params.get("code")
    state = request.query_params.get("state")

    # SECURITY CHECK: Verify state to prevent CSRF
    if state != db["state"]:
        raise HTTPException(status_code=400, detail="State mismatch! Security risk detected.")

    # Step 4: The Handshake (POST Request to Google)
    data = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(TOKEN_URL, data=data)
        tokens = response.json()

    if "error" in tokens:
        return {"error": tokens}

    db["tokens"] = tokens
    return RedirectResponse("/dashboard")

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Step 5: Use the Access Token"""
    access_token = db["tokens"].get("access_token")
    if not access_token:
        return RedirectResponse("/")

    # Fetch user info using the token in the Header
    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {access_token}"}
        user_info = await client.get("https://www.googleapis.com/oauth2/v3/userinfo", headers=headers)
        user_data = user_info.json()

    return f"""
    <html>
        <body>
            <h1>Welcome, {user_data.get('name')}</h1>
            <img src="{user_data.get('picture')}" width="100">
            <p>Email: {user_data.get('email')}</p>
            <h3>Raw Tokens Received:</h3>
            <pre>{str(db['tokens'])}</pre>
            <a href="/">Logout (Clear DB)</a>
        </body>
    </html>
    """

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8000)