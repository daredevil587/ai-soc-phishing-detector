from imapclient import IMAPClient
import pyzmail


def fetch_last_emails(email_user, email_pass, count=5):
    emails = []

    try:
        with IMAPClient('imap.gmail.com') as server:
            server.login(email_user, email_pass)
            server.select_folder('INBOX', readonly=True)

            messages = server.search(['ALL'])
            latest_messages = messages[-count:]

            for msg_id in latest_messages:
                raw_message = server.fetch([msg_id], ['BODY[]'])
                message = pyzmail.PyzMessage.factory(
                    raw_message[msg_id][b'BODY[]']
                )

                subject = message.get_subject()
                from_address = message.get_addresses('from')[0][1]

                if message.text_part:
                    body = message.text_part.get_payload().decode(
                        message.text_part.charset or 'utf-8',
                        errors='ignore'
                    )
                else:
                    body = ""

                emails.append({
                    "sender": from_address,
                    "subject": subject,
                    "body": body
                })

    except Exception as e:
        print("Error fetching emails:", e)

    return emails