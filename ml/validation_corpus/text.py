"""Static predeclared artifact removal, without learning from holdout text."""
import re
from ml.text import message_parts
from ml.generalization.text import feature_text as v2_feature_text

VERSION = "readable_real_world_v1"
LABEL_PREFIX = re.compile(r"(?im)^\s*(?:(?:\[(?:phishing|spam|ham|legitimate|benign)\]\s*)|(?:(?:phishing|spam|ham|legitimate|benign)\s*:\s*))+")
INJECTED = re.compile(r"(?im)^\s*(?:x-[\w-]+|label|class|target|ground[-_ ]truth|folder|path|split|generated[-_ ]by|generator|model[-_ ]name|prompt|system|assistant)\s*[:=].*(?:\n[ \t]+[^\n]*)*")
FOLDERS = re.compile(r"(?i)(?<!\w)(?:[a-z]:)?[\\/]?(?:(?:datasets?|corpus|train|training|validation|test|spam|ham|phishing|legitimate|inbox)[\\/])+[\w./\\-]*")
GENERATORS = re.compile(r"(?im)^\s*(?:here (?:is|are) (?:the |an? )?(?:generated |synthetic )?(?:phishing |legitimate |benign )?emails?\b.*|(?:this (?:email|message) (?:was|is) )?generated (?:by|using|with)\b.*|as an ai language model\b.*)$")
COLLECTORS = re.compile(r"(?i)\b(?:spaphish|smishx|phishing[_ -]pot|gemini[- ]?2\.5[- ]?flash|chatgpt|wormgpt)\b")
PATTERNS = {"label_prefix": LABEL_PREFIX, "injected_metadata": INJECTED,
            "folder_path": FOLDERS, "generator_line": GENERATORS, "collector": COLLECTORS}

def scrub(text):
    # Iterate twice for nested wrappers such as "phishing: spam: Subject".
    for _ in range(2):
        for pattern in PATTERNS.values():
            text = pattern.sub(" ", text)
    return text

def feature_text(value):
    subject, body = message_parts(value)
    return v2_feature_text({"subject": scrub(subject), "body": scrub(body)})
