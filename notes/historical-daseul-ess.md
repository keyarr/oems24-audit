# Historical DASEUL ESS request

This note records historical public evidence separately from the S24 firmware evidence in this repository. It narrows questions about the ESS request layout, but it does not show that the current authority issues mode 3 or that the current trustlet accepts this old schema.

Source consulted on 2026-08-24:

- GSM Hosting Forum, "Samsung EngineeringMode... eToken": https://forum.gsmhosting.com/vbb/f83/samsung-engineeringmode-etoken-3142461/index3.html
- Public post reporting a historical token with modes `3_4_5_10_21_28`: https://forum.gsmhosting.com/vbb/14926878-post25.html

The historical request was reported in this shape:

```text
01:DASEUL_EMR:1:<modes>:20191209:20191111:DASEUL:9999:995:<cert>
```

`<modes>` and `<cert>` stand for values omitted here. The request is evidence about an older DASEUL workflow, not a byte-for-byte sample produced from the audited S24.

| Segment | Literal observation | Proposed interpretation | Confidence | Applicability to the current S24 parser |
| --- | --- | --- | --- | --- |
| 1 | `01` | Protocol/schema version | High for the literal, medium for the role | The current parser also checks a version, but continuity is not established. |
| 2 | `DASEUL_EMR` | Protocol or request profile identifier | High for the literal, medium for the role | No proof that the current authority or parser accepts this identifier. |
| 3 | `1` | Unknown flag or request subtype | Low | Unmapped. |
| 4 | `<modes>` | Requested Engineering Mode list | High | Consistent with current mode serialization, but the representation changed. |
| 5 | `20191209` | Date-like value | High that it is a date, low for exact meaning | Could be issuance, validity or job metadata. The sample alone cannot decide. |
| 6 | `20191111` | Date-like value | High that it is a date, low for exact meaning | Same limitation as the previous field. |
| 7 | `DASEUL` | Tool, profile or provisioning class | High for the literal, medium for the role | Historical DASEUL material associates the word with `SINGLE`, but no current mapping is proven. |
| 8 | `9999` | Unknown numeric field | Low | Unmapped. |
| 9 | `995` | Probable certificate length | Medium | The reported certificate begins with DER header `30 82 03 df`, whose encoded total size is 995 bytes including the header. The complete certificate was not preserved in this repository, so this remains a strong hypothesis rather than a reproduced byte count. |
| 10 | `<cert>` | DER certificate or certificate-bearing blob | Medium to high | The current flow uses certificate-backed signed material, but schema compatibility is not established. |

The current trustlet evidence establishes structural checks for its own ESS input, including delimiters, a version field and length validation. It does not establish that the old DASEUL field values are still valid. The useful next question is therefore not "what are eight mysterious fields?" but "how does the current 12-segment ESS schema map to this historical DASEUL schema?"

Evidence boundaries:

- A historical report of a token containing mode 3 shows that mode 3 appeared in at least one older Engineering Mode workflow.
- It does not show that Samsung's current authority issues mode 3 for an SM-S928B retail DID.
- Dates are recognizable as dates, but assigning issuance and expiry semantics would be speculation.
- `995` matches the DER size encoded by the reported header, but the full blob is required for a reproducible count.
- No historical forum claim is used as proof of current bootloader or trustlet behavior.
