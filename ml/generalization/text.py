"""Fixed metadata scrubbing layered on the preserved v1 readable normalizer."""
import re

from ml.text import feature_text as legacy_feature_text, message_parts

VERSION = "readable_source_masked_v2"
METADATA_LINE = re.compile(
    r"(?im)^\s*(?:dataset(?:[-_ ]name)?|source(?:[-_ ](?:id|file))?|filename|"
    r"label|category|phishing_type|severity|confidence|created[-_ ]by|"
    r"generation[-_ ]model|collection[-_ ](?:id|date)|sample[-_ ]id)\s*[:=].*$")
FILENAME = re.compile(
    r"(?i)(?<!\w)(?:[\w.-]+[/\\])*[\w.-]+\.(?:csv|jsonl?|parquet|eml|mbox|txt)(?!\w)")
COLLECTOR = re.compile(
    r"(?i)\b(?:trec[-_ ]?0[567]|ceas[-_ ]?0?8|ling[-_ ]spam|"
    r"synthetic[-_ ]emails(?:[-_ ]poisoned)?|phishing[-_ ]legit[-_ ]dataset[-_ ]kd|"
    r"kuladeep19|yoadjei|phishnchips|data[-_ ]?phish|meajor)\b")


def feature_text(value):
    subject, body = message_parts(value)
    def clean(text):
        text = METADATA_LINE.sub(" ", text)
        text = FILENAME.sub(" ", text)
        return COLLECTOR.sub(" ", text)
    return legacy_feature_text({"subject": clean(subject), "body": clean(body)})
