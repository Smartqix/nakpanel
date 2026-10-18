"""Read private QA state from stdin; verify TLS, reset, alias delivery and IMAP."""
import email.message
import imaplib
import json
import smtplib
import ssl
import sys
import time

state = json.load(sys.stdin)
assert state["address"].startswith(state["prefix"] + "@")
host = "mail.nakpanel.com"
context = ssl.create_default_context()
for attempt in range(30):
    try:
        mailbox = imaplib.IMAP4_SSL(host, 993, ssl_context=context, timeout=10)
        mailbox.login(state["address"], state["password"])
        break
    except imaplib.IMAP4.error:
        if attempt == 29:
            raise RuntimeError("QA mailbox did not converge") from None
        time.sleep(2)
else:
    raise RuntimeError("QA mailbox unavailable")
try:
    old = imaplib.IMAP4_SSL(host, 993, ssl_context=context, timeout=10)
    try:
        old.login(state["address"], state["oldPassword"])
    except imaplib.IMAP4.error:
        pass
    else:
        raise RuntimeError("Old mailbox password still accepted")
    finally:
        old.shutdown()
    message = email.message.EmailMessage()
    message["From"] = state["address"]
    message["To"] = state["alias"]
    message["Subject"] = "Nakpanel Mail UX verification " + state["prefix"]
    message.set_content("Synthetic QA delivery. No customer data.")
    with smtplib.SMTP_SSL(host, 465, context=context, timeout=15) as smtp:
        smtp.login(state["address"], state["password"])
        smtp.send_message(message)
    with smtplib.SMTP(host, 587, timeout=15) as smtp:
        smtp.starttls(context=context)
        smtp.login(state["address"], state["password"])
    for attempt in range(30):
        mailbox.select("INBOX")
        status, messages = mailbox.search(None, "SUBJECT", '"' + message["Subject"] + '"')
        if status == "OK" and messages[0]:
            break
        time.sleep(2)
    else:
        raise RuntimeError("Alias message did not arrive in the QA IMAP inbox")
    print(json.dumps({"ok": True, "checks": ["IMAP TLS login", "old password denied", "SMTP TLS auth", "SMTP STARTTLS auth", "alias delivery", "IMAP retrieval"]}))
finally:
    mailbox.logout()
