# Detection Rule Library

A curated collection of detection rules for SOC operations — Sigma rules, YARA signatures, and Splunk SPL queries. Every rule in this repo has been tested against real tool execution in an isolated lab environment.

**Author:** Gabriel Lopez ([@Dito231](https://github.com/Dito231))

## Structure

```
detection-rules/
├── sigma/                    # Sigma rules (vendor-agnostic)
│   ├── credential_access/    # T1003 - Credential dumping
│   ├── persistence/          # T1547 - Registry run keys, etc.
│   ├── execution/            # T1059 - Scripting, T1218 - Signed binary abuse
│   ├── command_and_control/  # T1071 - C2 communication
│   └── defense_evasion/      # T1036 - Masquerading, T1562 - Disable defenses
├── yara/                     # YARA rules for file/memory scanning
│   └── emotet_loader.yar     # Emotet DLL loader (2 rules)
├── splunk/                   # Splunk SPL translations
│   ├── lsass_memory_access.spl
│   ├── emotet_execution_chain.spl
│   ├── rundll32_outbound_http.spl
│   ├── self_deletion_via_cmd.spl
│   ├── mythic_apollo_agent.spl
│   ├── defender_realtime_disabled.spl
│   ├── ssh_brute_force.spl
│   └── rdp_brute_force.spl
└── README.md
```

## Coverage Matrix

| Rule | MITRE ATT&CK | Telemetry Source | Tested Against |
|------|-------------|-----------------|---------------|
| LSASS Memory Access | T1003.001 | Sysmon Event 10 | Mimikatz, comsvcs.dll, procdump |
| Emotet Loader | T1566.001 | File scan | Emotet DLL samples |
| Registry Run Key Persistence | T1547.001 | Sysmon Event 13 | Emotet, manual |
| Suspicious Process Lineage | T1218.010 | Sysmon Event 1 | regsvr32→rundll32 chain |
| SSH Brute Force | T1110.001 | auth.log | Crowbar, Hydra |
| RDP Brute Force | T1110.001 | Windows Event 4625 | Crowbar |
| C2 Beaconing (Mythic/Apollo) | T1071.001 | Sysmon Event 3 | Mythic Apollo agent |
| Defender Disabled | T1562.001 | Windows Event 5001 | Manual |
| Self-Deletion via cmd | T1070.004 | Sysmon Event 1 | Emotet |
| Rundll32 Network Connection | T1218.011 | Sysmon Event 3 | Emotet C2 callback |

## Usage

### Sigma Rules
Sigma rules are vendor-agnostic and can be converted to your SIEM's query language using [sigma-cli](https://github.com/SigmaHQ/sigma-cli) or [pySigma](https://github.com/SigmaHQ/pySigma):

```bash
# Convert to Splunk
sigma convert -t splunk sigma/credential_access/lsass_memory_access.yml

# Convert to Elastic
sigma convert -t elasticsearch sigma/credential_access/lsass_memory_access.yml
```

### YARA Rules
```bash
yara -r yara/emotet_loader.yar /path/to/samples/
```

### Splunk SPL
Each `.spl` file contains a ready-to-use Splunk query. Copy into Splunk's search bar or use as the basis for a correlation search / alert.

## Testing Methodology

Every rule in this repo follows the same lifecycle:

1. **Research** the technique (MITRE ATT&CK, vendor reports, threat intel)
2. **Map telemetry** — identify which log source and fields detect the behavior
3. **Write the rule** in Sigma (vendor-agnostic first)
4. **Test against real execution** in an isolated lab (FlareVM + REMnux + Elastic)
5. **Tune false positives** by running against normal baseline activity
6. **Translate** to Splunk SPL and document

Rules that haven't been tested against real tool execution are not included. If a rule is in this repo, it fires.

## Related

- [MyDFIR 30-Day Challenge Writeup] (https://dito-portfolio.neocities.org/blog/mydfir-part1-soc-lab) — the lab environment where these rules were developed
- [Malware Analysis Lab Build](https://dito-portfolio.neocities.org/blog/lab-build) — the FlareVM + REMnux setup used for testing

## License

MIT — use these rules however you want. Attribution appreciated but not required.
