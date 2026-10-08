import imaplib
import email
import time
import os
import logging
from dotenv import load_dotenv

# Import core detection routines from your main engine
from phishing_detector import (
    analyze_message,
    enrich_analysis_with_virustotal,
    calculate_phishing_risk,
    export_json_log,
    generate_analyst_report,
)

# Configure logging for the daemon process
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)

load_dotenv()

IMAP_SERVER = os.getenv("IMAP_SERVER", "imap.gmail.com")
IMAP_PORT = int(os.getenv("IMAP_PORT", 993))
IMAP_USER = os.getenv("IMAP_USER")
IMAP_PASSWORD = os.getenv("IMAP_PASSWORD")
IMAP_FOLDER = os.getenv("IMAP_FOLDER", "INBOX")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", 10))


def connect_to_mailbox():
    """Establish a secure SSL connection to the IMAP server."""
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        mail.login(IMAP_USER, IMAP_PASSWORD)
        logging.info(f"Successfully connected to {IMAP_SERVER} as {IMAP_USER}")
        return mail
    except Exception as e:
        logging.error(f"Failed to connect to mailbox: {e}")
        return None


def process_unread_emails(mail):
    """Fetch and process unread messages from the inbox in controlled batches."""
    mail.select(IMAP_FOLDER)
    status, response = mail.search(None, "UNSEEN")

    if status != "OK":
        logging.warning("Failed to search inbox for UNSEEN messages.")
        return

    email_ids = response[0].split()
    if not email_ids:
        logging.debug("No new unread emails found.")
        return

    # Process in batches of 10 to protect API rate limits
    batch = email_ids[:10]
    logging.info(f"Found {len(email_ids)} unread email(s). Processing batch of {len(batch)}...")

    for e_id in batch:
        try:
            # Fetch raw message
            _, msg_data = mail.fetch(e_id, "(RFC822)")
            raw_email_bytes = msg_data[0][1]
            raw_mime_string = raw_email_bytes.decode("utf-8", errors="replace")

            msg = email.message_from_bytes(raw_email_bytes)
            subject = msg.get("Subject", "(No Subject)")

            # Extract body
            body_content = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition"))
                    if content_type == "text/plain" and "attachment" not in content_disposition:
                        body_content = part.get_payload(decode=True).decode("utf-8", errors="replace")
                        break
            else:
                body_content = msg.get_payload(decode=True).decode("utf-8", errors="replace")

            logging.info(f"Analyzing message: '{subject}'")

            # Core analysis pipeline
            results = analyze_message(body_content, raw_mime_string=raw_mime_string)
            results = enrich_analysis_with_virustotal(results)
            phishing_risk = calculate_phishing_risk(results)

            # Log outputs
            export_json_log(results, phishing_risk, output_file="phishing_events.json")
            if phishing_risk["score"] >= 30:
                generate_analyst_report(results, phishing_risk, output_file="analyst_report.html")

            logging.info(
                f"Analysis Complete | Subject: '{subject}' | Score: {phishing_risk['score']} | Verdict: {phishing_risk['verdict']}"
            )

            # Mark message as SEEN in Gmail
            mail.store(e_id, "+FLAGS", "\\Seen")

        except Exception as e:
            logging.error(f"Error processing email ID {e_id}: {e}")

def run_daemon():
    """Main execution loop for continuous polling."""
    logging.info("Starting Phishing Engine Live Ingestion Daemon...")
    
    while True:
        mail = connect_to_mailbox()
        if mail:
            try:
                process_unread_emails(mail)
                mail.logout()
            except Exception as e:
                logging.error(f"Unexpected error during daemon loop: {e}")
        
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run_daemon()