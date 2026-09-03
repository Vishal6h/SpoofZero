from email import policy
from email.parser import BytesParser
from pathlib import Path


def parse_email(file_path):
    file_path = Path(file_path)

    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    email_data = {
        "subject": msg.get("Subject"),
        "from": msg.get("From"),
        "to": msg.get("To"),
        "reply_to": msg.get("Reply-To"),
        "return_path": msg.get("Return-Path"),
        "message_id": msg.get("Message-ID"),
        "date": msg.get("Date"),
        "received": msg.get_all("Received", []),
        "authentication_results": msg.get_all(
            "Authentication-Results", []
        ),
        "body": ""
    }

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()

            if content_type == "text/plain":
                try:
                    email_data["body"] += part.get_content()
                except Exception:
                    pass
    else:
        try:
            email_data["body"] = msg.get_content()
        except Exception:
            pass

    return email_data


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) != 2:
        print("Usage: python email_parser.py <email.eml>")
        sys.exit(1)

    result = parse_email(sys.argv[1])

    print(json.dumps(result, indent=4, default=str))
