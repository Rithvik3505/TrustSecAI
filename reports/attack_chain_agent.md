# TrustSecAI Attack-Chain Prediction Agent

## Purpose

The attack-chain prediction agent provides a bounded, defensive hypothesis about likely follow-up investigation areas after an IDS alert. It helps SOC analysts move from a single alert label toward a structured assessment of possible tactics, defensive checks, and mitigations.

The agent does not provide offensive instructions. It does not claim attacker intent, attribution, or confirmed compromise. Its output is a prioritization aid for defensive investigation.

## Current Scope

The current implementation uses static ATT&CK seed mappings for the final demo. This was chosen to keep the demo deterministic and presentation-ready while avoiding additional Neo4j traversal work during the final project window.

## Seed Mappings

| IDS label | ATT&CK seed technique | Primary tactic |
|---|---|---|
| Web Attack - Sql Injection | `T1190` Exploit Public-Facing Application | Initial Access |
| PortScan | `T1046` Network Service Discovery | Discovery |
| FTP-Patator | `T1110` Brute Force | Credential Access |
| Bot | `T1105` Ingress Tool Transfer | Command and Control |
| DDoS | `T1498` Network Denial of Service | Impact |

## Outputs

For each IDS label, the agent returns:

- Seed technique
- Likely next tactics/techniques
- Defensive mitigations
- Caveats
- Confidence

Every output is framed as a defensive hypothesis. The caveats explicitly state that ATT&CK mappings and graph context are contextual intelligence, not proof of attacker behavior.

## Five-Case Demo Coverage

| IDS label | example_id | Agent demonstration |
|---|---|---|
| Web Attack - Sql Injection | `trustsecai-gold-v1-00575` | Demonstrates a public-facing application exploitation seed with bounded follow-up around execution, credential exposure risk, and exfiltration review. |
| PortScan | `trustsecai-gold-v1-00178` | Demonstrates discovery-stage reasoning from network service discovery toward remote service and brute-force investigation priorities. |
| FTP-Patator | `trustsecai-gold-v1-00810` | Demonstrates credential-access reasoning from brute force toward valid-account review and post-authentication activity checks. |
| Bot | `trustsecai-gold-v1-00381` | Demonstrates command-and-control/tool-transfer context while preserving explicit no-attribution framing. |
| DDoS | `trustsecai-gold-v1-00128` | Demonstrates impact-focused reasoning for denial-of-service handling, service disruption review, and traffic-filtering mitigations. |

## Defensive Caveats

- The agent does not generate exploitation steps.
- The agent does not confirm compromise.
- The agent does not attribute activity to groups, malware, or tools.
- Candidate next steps are investigation priorities, not a predicted attacker plan.
- Missing CVE, asset exposure, or temporal correlation evidence is surfaced as a limitation.

## Future Work

- Replace static mappings with Neo4j graph traversal.
- Rank candidate next techniques using graph evidence, relationship confidence, and source provenance.
- Include temporal alert correlation across multiple IDS events.
- Calibrate confidence using historical incident data and analyst feedback.
- Incorporate CAPEC/CWE/CVE paths where vulnerability evidence is actually present.
- Add suppression logic for unsupported candidate paths when graph context is sparse.

