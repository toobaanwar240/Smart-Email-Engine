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
    "openid",
    "https://www.googleaps.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/calendar.events",
    "openid",
]


def authenticate_gmail():
    """
    Streamlit Cloud-friendly Gmail authentication.
    Uses st.session_state to store credentials. No local files.
    Works with a single redirect URI.
    """

    # --- 1. Return valid creds from session if available ---
    if "creds" in st.session_state:
        creds = st.session_state["creds"]
        if creds and creds.valid:
            return creds
        elif creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                st.session_state["creds"] = creds
                return creds
            except Exception as e:
                st.warning(f"Session expired. Please login again: {e}")

    # --- 2. OAuth client configuration ---
    client_id = st.secrets["google"]["client_id"]
    client_secret = st.secrets["google"]["client_secret"]
    redirect_uri = st.secrets["google"]["redirect_uri"]  # Cloud URL

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

    # --- 3. Handle redirect from Google ---
    query_params = st.experimental_get_query_params()
    if "code" in query_params:
        try:
            code = query_params["code"][0]
            flow.fetch_token(code=code)
            creds = flow.credentials
            st.session_state["creds"] = creds

            # Clear URL query params to avoid repeated login
            st.experimental_set_query_params()
            st.experimental_rerun()
        except Exception as e:
            st.error(f"Authentication failed: {e}")
            st.stop()

    # --- 4. Show login button if not authenticated ---
    else:
        auth_url, _ = flow.authorization_url(prompt="consent", access_type="offline")
        st.markdown(
            f'<a href="{auth_url}" target="_self">'
            '<button style="padding:10px 20px;background-color:#4285F4;color:white;'
            'border:none;border-radius:4px;font-size:16px;cursor:pointer;">'
            '🔐 Login with Google</button></a>',
            unsafe_allow_html=True,
        )
        st.stop()

    return st.session_state.get("creds")

    
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
