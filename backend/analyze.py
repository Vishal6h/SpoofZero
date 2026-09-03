import sys
import json

from .analyzers.email_parser import parse_email
from .analyzers.header_analyzer import analyze_sender_identity
from .analyzers.auth_analyzer import analyze_authentication
from .analyzers.ioc_extractor import extract_iocs, sha256_file
from .analyzers.relay_tracer import trace_relays
from .analyzers.nlp_detector import analyze_text
from .analyzers.geo_analyzer import geolocate_ip
from .analyzers.threat_intel import analyze_domains
from .analyzers.reputation_analyzer import analyze_reputation, analyze_attachment_reputation
from .analyzers.attachment_analyzer import analyze_attachments
from .analyzers.fusion_engine import calculate_final_risk


def analyze_email(file_path):

    email_data = parse_email(
        file_path
    )

    sender_identity = analyze_sender_identity(
        email_data
    )

    authentication = analyze_authentication(
        email_data
    )

    iocs = extract_iocs(
        email_data
    )

    relay_trace = trace_relays(
        email_data
    )

    ai_analysis = analyze_text(
        email_data
    )

    attachments = analyze_attachments(
        file_path
    )

    candidate_ip = relay_trace.get(
        "candidate_origin_ip"
    )

    threat_intelligence = analyze_domains(
        iocs.get("domains", [])
    )

    reputation = analyze_reputation(
        iocs,
        candidate_ip
    )

    attachment_reputation = analyze_attachment_reputation(
        attachments
    )

    if candidate_ip:

        geo_analysis = geolocate_ip(
            candidate_ip
        )

    else:

        geo_analysis = {
            "status": "not_available",
            "message": (
                "No reliable public origin IP was "
                "identified in the relay chain."
            )
        }

    final_assessment = calculate_final_risk(
        sender_identity,
        authentication,
        relay_trace,
        ai_analysis,
        reputation,
        attachment_reputation
    )

    return {
        "email": {
            "subject": email_data.get("subject"),
            "from": email_data.get("from"),
            "to": email_data.get("to"),
            "date": email_data.get("date"),
            "reply_to": email_data.get("reply_to"),
            "return_path": email_data.get("return_path"),
            "message_id": email_data.get("message_id"),
            "sha256": sha256_file(file_path)
        },

        "final_assessment": final_assessment,
        "ai_analysis": ai_analysis,
        "sender_identity": sender_identity,
        "authentication": authentication,
        "iocs": iocs,
        "attachments": attachments,
        "attachment_reputation": attachment_reputation,
        "reputation": reputation,
        "threat_intelligence": threat_intelligence,
        "relay_trace": relay_trace,
        "geo_analysis": geo_analysis
    }


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print(
            "Usage: python -m backend.analyze "
            "<email.eml>"
        )
        sys.exit(1)

    print(
        json.dumps(
            analyze_email(
                sys.argv[1]
            ),
            indent=4
        )
    )
