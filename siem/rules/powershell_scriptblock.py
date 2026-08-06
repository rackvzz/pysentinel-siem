"""T1059.001 - Command and Scripting Interpreter: PowerShell
https://attack.mitre.org/techniques/T1059/001/

Fires on PowerShell Script Block Logging (event 4104, channel
Microsoft-Windows-PowerShell/Operational) when the *executed* script
block text contains a high-signal offensive-tooling or obfuscation
indicator.

This complements encoded_powershell.py rather than replacing it: that
rule matches the literal `-enc`/`-EncodedCommand` flag on the process's
command line, which a multi-stage attack can avoid entirely (e.g. an
already-encoded first stage that decodes and runs a *second* payload in
memory, never passing another `-enc` flag anywhere). Script block logging
instead captures what PowerShell's own engine actually parses and runs --
including content decoded/reconstructed by the first stage -- so it
catches obfuscation techniques (string-building, `-join`, `[char]`
concatenation, `FromBase64String` calls buried in the script itself) the
command-line check structurally can't see.

Deliberately NOT flagging every 4104 event: with the policy enabled,
*everything* you run generates one (including totally ordinary admin
work), so this only fires on a curated set of known-bad indicators
rather than trying to score "how obfuscated is this" in general -- that
keeps it explainable and low-noise instead of a black box.
"""

from .. import alerts
from ..normalize import parse_event_data
from .base import Rule

# Named offensive-tooling functions/cmdlets -- if a script block contains
# one of these by name, that's a strong signal on its own regardless of
# anything else in the script.
OFFENSIVE_TOOL_NAMES = (
    "invoke-mimikatz",
    "invoke-reflectivepeinjection",
    "invoke-shellcode",
    "invoke-tokenmanipulation",
    "invoke-dllinjection",
    "invoke-portscan",
    "powersploit",
)

# A "download cradle" -- fetch content over the network, then execute it
# immediately -- is one of the most common ways a script pulls a second
# stage. Neither half is suspicious alone (IEX and web requests both have
# ordinary uses); the combination in the same block is the actual signal.
DOWNLOAD_METHODS = ("downloadstring", "downloadfile", "downloaddata", "net.webclient", "invoke-webrequest", "iwr ")
EXECUTION_METHODS = ("invoke-expression", "iex(", "iex ", "invoke-command")

EXPLICIT_ENCODED_FLAGS = ("-encodedcommand", "-enc ")


def _classify(text: str) -> str | None:
    """Returns a short reason string if `text` (already lowercased) trips
    an indicator, else None."""
    for name in OFFENSIVE_TOOL_NAMES:
        if name in text:
            return f"references known offensive-tooling function '{name}'"

    if any(flag in text for flag in EXPLICIT_ENCODED_FLAGS):
        return "uses -EncodedCommand"

    if any(dl in text for dl in DOWNLOAD_METHODS) and any(ex in text for ex in EXECUTION_METHODS):
        return "downloads and immediately executes content (download cradle)"

    if "frombase64string" in text and any(ex in text for ex in EXECUTION_METHODS):
        return "decodes and immediately executes a base64 blob"

    return None


class PowerShellScriptBlockRule(Rule):
    id = "powershell_scriptblock"
    name = "Suspicious PowerShell Script Block"
    mitre_id = "T1059.001"
    severity = "high"

    def __init__(self, event_id: int = 4104):
        self.event_id = event_id

    def evaluate(self, conn, event: dict, row_id: int) -> None:
        if event["event_id"] != self.event_id:
            return

        data = parse_event_data(event["raw_xml"])
        script_text = data.get("ScriptBlockText") or ""
        if not script_text:
            return

        reason = _classify(script_text.lower())
        if reason is None:
            return

        alerts.raise_alert(
            conn,
            rule_id=self.id,
            mitre_id=self.mitre_id,
            severity=self.severity,
            description=(
                f"Suspicious PowerShell script block on {event['computer']} -- {reason}: "
                f"{script_text.strip()[:200]}"
            ),
            event_id_ref=row_id,
        )
