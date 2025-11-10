import os.path
import os
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import streamlit as st
from dotenv import load_dotenv
from urllib.parse import urlparse, parse_qs
from googleapiclient.errors import HttpError
from calender import process_email
from caption_emails import caption_email
from send_email import create_message, get_email_content, get_mime_message, send_message
from summarize_emails import summarize_email

load_dotenv()

# Define the Gmail/Calendar scopes
SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/calendar.events"
]

def authenticate_gmail():
    """Fully automatic OAuth login (no URL pasting required)."""
    creds = None

    # --- 1. Check session state first ---
    if "creds" in st.session_state and st.session_state.get("creds"):
        creds = st.session_state["creds"]
        if creds and creds.valid:
            return creds
        elif creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                st.session_state["creds"] = creds
                return creds
            except:
                pass  # Will re-authenticate below

    # --- 2. Load existing token if available (local only) ---
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
        if creds and creds.valid:
            st.session_state["creds"] = creds
            return creds

    # --- 3. If no valid credentials, start OAuth flow ---
    if not creds or not creds.valid:
        # Get credentials
        client_id = st.secrets["google"]["client_id"]
        client_secret = st.secrets["google"]["client_secret"]

        # Detect environment - FIXED VERSION
        redirect_uri = "http://localhost:8501/"  # default for local
        
        # Check if running on Streamlit Cloud
        try:
            # Method 1: Check hostname
            import socket
            hostname = socket.gethostname()
            if "streamlit" in hostname.lower():
                redirect_uri = "https://mailsense.streamlit.app/"
        except:
            pass
        
        # Method 2: Check for Streamlit Cloud environment variable
        if os.getenv("STREAMLIT_SHARING_MODE") or os.getenv("IS_STREAMLIT_CLOUD"):
            redirect_uri = "https://mailsense.streamlit.app/"
        
        # Method 3: Force cloud URL if secrets are from Streamlit Cloud
        # (Streamlit Cloud always has secrets, local might use .env)
        try:
            if hasattr(st, 'secrets') and 'google' in st.secrets:
                # If we can access st.secrets, we might be on cloud
                # You can add a flag in secrets to indicate cloud
                redirect_uri = st.secrets.get("redirect_uri", redirect_uri)
        except:
            pass

        # Initialize OAuth flow
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [redirect_uri],
                }
            },
            scopes=SCOPES,
        )
        flow.redirect_uri = redirect_uri

        # --- 4. Handle redirect automatically ---
        query_params = st.query_params

        if "code" not in query_params:
            # Not logged in yet → show login button
            auth_url, _ = flow.authorization_url(prompt="consent", access_type="offline")
            st.markdown(
                f'<a href="{auth_url}" target="_self">'
                '<button style="padding:8px 16px;background-color:#4285F4;color:white;border:none;border-radius:4px;">'
                'Login with Gmail</button></a>',
                unsafe_allow_html=True,
            )
            st.stop()
        else:
            # User returned from Google with ?code=...
            auth_code = query_params["code"]
            flow.fetch_token(code=auth_code)
            creds = flow.credentials

            # Save to session state (persists during session)
            st.session_state["creds"] = creds
            
            # Save to file (for local development only)
            try:
                with open("token.json", "w") as token_file:
                    token_file.write(creds.to_json())
            except:
                pass  # File system might be read-only on cloud

            st.success("✅ Logged in successfully!")
            st.query_params.clear()  # clean up URL
            st.rerun()

    return creds
    
def get_gmail_service():
    """Return Gmail API service object"""
    creds = authenticate_gmail()
    return build("gmail", "v1", credentials=creds)

def get_calendar_service():
    """Return Google Calendar API service object"""
    creds = authenticate_gmail()
    return build("calendar", "v3", credentials=creds)

def list_labels(service):
    """List Gmail labels for the authenticated user"""
    results = service.users().labels().list(userId="me").execute()
    labels = results.get("labels", [])
    if labels:
        print("Labels:")
        for label in labels:
            print(label["name"])
    else:
        print("No labels found.")

def send_test_email(service, sender, recipient):
    """Send a test email"""
    msg = create_message(
        sender=sender,
        to=recipient,
        subject="Test Gmail API",
        message_text="Hello from Python Gmail API! Let's schedule our project discussion meeting on October 30, 2025, at 3:30 PM."
    )
    send_message(service, "me", msg)

  
def fetch_latest_email(service):
    """Fetch latest email from inbox and return content"""
    results = service.users().messages().list(userId='me', maxResults=1, labelIds=['INBOX']).execute()
    messages = results.get('messages', [])
    if not messages:
        print("No new messages.")
    else:
        latest_msg_id = messages[0]['id']
        mime_msg = get_mime_message(service, "me", latest_msg_id)
        if mime_msg:
            content = get_email_content(mime_msg)
            print("Original email: \n",content)
            caption = caption_email(content)
            print("Email Caption: \n",caption)
            summary = summarize_email(content)
            print("Summarized email: \n",summary)
            process_email(content)

def process_latest_email(service):
    """Fetch, summarize, and process the latest email"""
    content = fetch_latest_email(service)
    if content:
        print("Original email:\n", content)
        summary = summarize_email(content)
        print("Summarized email:\n", summary)
        process_email(content)

def main():
    creds = authenticate_gmail()
    try:
        service = build("gmail", "v1", credentials=creds)
        list_labels(service)
        send_test_email(service, sender="toobaanwar240@gmail.com", recipient="toobaanwar240@gmail.com")
        process_latest_email(service)
    except HttpError as error:
        print(f"An error occurred: {error}")

if __name__ == "__main__":
    main()
