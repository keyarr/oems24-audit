# Historical DASEUL ESS request

This note records historical public evidence separately from the S24 firmware evidence in this repository. It narrows questions about the ESS request layout, but it does not show that the current authority issues mode 3 or that the current trustlet accepts this old schema.

Source consulted on 2026-08-24:

- GSM Hosting Forum, "Samsung EngineeringMode... eToken": https://forum.gsmhosting.com/vbb/f83/samsung-engineeringmode-etoken-3142461/index3.html
- Public post reporting a historical token with modes `3_4_5_10_21_28`: https://forum.gsmhosting.com/vbb/14926878-post25.html

The complete command in post #40 was reported in this shape:

```text
01:DASEUL_EMR:1:<modes>:20191209:20191111:DASEUL:9999:995:<cert>:<sha256>:
```

`<modes>`, `<cert>` and `<sha256>` stand for values abbreviated here. The post's full command has 11 nonempty tokens plus the empty component after the terminal `:`. The request is evidence about an older DASEUL workflow, not a byte-for-byte sample produced from the audited S24.

| Segment | Literal observation | Proposed interpretation | Confidence | Applicability to the current S24 parser |
| --- | --- | --- | --- | --- |
| 1 | `01` | Protocol/schema version | High for the literal, medium for the role | The current parser also checks a version, but continuity is not established. |
| 2 | `DASEUL_EMR` | Protocol or request profile identifier | Likely | Positionally maps to current `field_0`; no proof that the current authority accepts this identifier. |
| 3 | `1` | Small profile/version/server-type value | Possible | Positionally maps to current `field_1`; the current parser keeps it opaque. |
| 4 | `<modes>` | Requested Engineering Mode list | Likely | Positionally maps to current `field_2`; current code forwards it but does not parse it. |
| 5 | `20191209` | Date-like value A | Likely as date, unknown exact role | Positionally maps to current `field_3`; only digit validation is confirmed. |
| 6 | `20191111` | Date-like value B | Likely as date, unknown exact role | Positionally maps to current `field_4`; only digit validation is confirmed. |
| 7 | `DASEUL` | Single ID or provisioning identity | Likely | Positionally maps to current `field_5`; historical material also shows `SINGLE : DASEUL`. |
| 8 | `9999` | Short credential or policy value | Possible | Positionally maps to current `field_6`; OTP and validity-count interpretations both remain open. |
| 9 | `995` | Certificate length | Likely | Positionally maps to current `cert_len`. DER header `30 82 03 df` encodes 995 bytes total. |
| 10 | `<cert>` | DER certificate | Likely | Positionally maps to current `cert_hex`; full trust-chain continuity is not established. |
| 11 | `<sha256>` | SHA-256 of the serialized body | Confirmed in current parser; historical recomputation pending | Positionally maps to current `sha256_hex`. |

The current trustlet evidence establishes structural checks for its own ESS input, including delimiters, a version field, SHA-256 and length validation. The complete DASEUL command maps positionally to the current seven-field prefix. It does not establish that the old values are still accepted or what names the backend assigns to them.

Evidence boundaries:

- A historical report of a token containing mode 3 shows that mode 3 appeared in at least one older Engineering Mode workflow.
- It does not show that Samsung's current authority issues mode 3 for an SM-S928B retail DID.
- Dates are recognizable as dates, but assigning issuance and expiry semantics would be speculation.
- `995` matches the DER size encoded by the reported header. The full blob and hash are still not preserved locally for a byte-for-byte recomputation.
- No historical forum claim is used as proof of current bootloader or trustlet behavior.
