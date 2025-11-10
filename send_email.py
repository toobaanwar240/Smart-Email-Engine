import base64
import email
from email.mime.text import MIMEText

def create_message(sender, to, subject, message_text):
  message = MIMEText(message_text)
  message['to'] = to
  message['from'] = sender
  message['subject'] = subject
  raw_message = base64.urlsafe_b64encode(message.as_string().encode("utf-8"))
  return {
    'raw': raw_message.decode("utf-8")
  }

def create_draft(service, user_id, message_body):
  try:
    message = {'message': message_body}
    draft = service.users().drafts().create(userId=user_id, body=message).execute()
    print("Draft id: %s\nDraft message: %s" % (draft['id'], draft['message']))
    return draft
  except Exception as e:
    print('An error occurred: %s' % e)
    return None
  
def send_message(service, user_id, message):
  try:
    message = service.users().messages().send(userId=user_id, body=message).execute()
    print('Message Id: %s' % message['id'])
    return message
  except Exception as e:
    print('An error occurred: %s' % e)
    return None
  
def get_messages(service, user_id):
  try:
    return service.users().messages().list(userId=user_id).execute()
  except Exception as error:
    print('An error occurred: %s' % error)

def get_message(service, user_id, msg_id):
  try:
    return service.users().messages().get(userId=user_id, id=msg_id, format='metadata').execute()
  except Exception as error:
    print('An error occurred: %s' % error)

def get_mime_message(service, user_id, msg_id):
  try:
    message = service.users().messages().get(userId=user_id, id=msg_id,
                                             format='raw').execute()
    print('Message snippet: %s' % message['snippet'])
    msg_str = base64.urlsafe_b64decode(message['raw'].encode("utf-8")).decode("utf-8")
    mime_msg = email.message_from_string(msg_str)
    return mime_msg
  except Exception as error:
    print('An error occurred: %s' % error)

def get_email_content(mime_msg):
    """
    Extracts the body content from a MIME message safely.
    Handles different encodings & avoids UnicodeDecodeError.
    Returns plain text if available, otherwise HTML.
    """
    def safe_decode(part):
        payload = part.get_payload(decode=True)
        if payload:
            # Detect declared charset if available
            charset = part.get_content_charset()
            if charset:
                try:
                    return payload.decode(charset, errors="replace")
                except:
                    pass
            # Fallback to UTF-8 safe decode
            return payload.decode("utf-8", errors="replace")
        return ""

    if mime_msg.is_multipart():
        for part in mime_msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            # Skip attachments
            if "attachment" in content_disposition:
                continue

            # Prefer plain text
            if content_type == "text/plain":
                return safe_decode(part)

        # Fallback: try HTML
        for part in mime_msg.walk():
            if part.get_content_type() == "text/html":
                return safe_decode(part)

    else:
        # Email is not multipart
        content_type = mime_msg.get_content_type()
        if content_type in ["text/plain", "text/html"]:
            return safe_decode(mime_msg)

    return ""
