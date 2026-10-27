# Network Intrusion Detection with Suricata

This lab runs Suricata, an intrusion detection system, against a packet capture and catches the attacks in the network traffic. The capture contains a TCP port scan and a web application attack (sqlmap running SQL injection), and Suricata detects both with custom rules. This is detection at the network layer, alongside the endpoint and cloud detection in the other labs.

## The setup

Suricata runs in Docker, reading a capture file offline. No live network needed, which is how an analyst triages a capture after the fact.

| | |
|---|---|
| IDS | Suricata (jasonish/suricata image) in Docker |
| Input | attack.pcap, a crafted capture of two attacks |
| Rules | custom rules in local.rules |

## The attacks in the capture

`data/attack.pcap` (built by `data/make_pcap.py`) contains:

1. **A TCP SYN port scan.** One host (`198.51.100.66`) sends SYN packets to 40 ports on a target (`192.0.2.5`), the classic sweep an attacker runs to find open services.
2. **A SQL injection over HTTP.** A full TCP session carrying a request from the sqlmap tool, with `' OR '1'='1` in the URI, the signature of automated SQL injection against a web app.

## The rules

`rules/local.rules` has three detections:

```
alert http any any -> any any (msg:"LAB Sqlmap scanner User-Agent"; flow:established,to_server; http.user_agent; content:"sqlmap"; nocase; sid:1000001;)
alert http any any -> any any (msg:"LAB SQL Injection attempt in URI"; flow:established,to_server; http.uri; content:"'1'='1"; nocase; sid:1000002;)
alert tcp any any -> any any (msg:"LAB TCP SYN port scan"; flags:S; threshold:type threshold, track by_src, count 20, seconds 60; sid:1000003;)
```

Reading them: the first fires on the sqlmap user agent, the second on the injection string in the URL, the third when one source sends 20 or more SYN packets in a minute (a scan). The `http.user_agent` and `http.uri` parts are sticky buffers, Suricata parses the HTTP out of the packets and matches on specific fields rather than raw bytes.

## Running it

```bash
docker run --rm -v "$(pwd)":/data jasonish/suricata:latest \
  -r /data/attack.pcap -S /data/local.rules -l /data
cat fast.log
```

`-r` reads the capture, `-S` loads only these rules, `-l` writes the logs out.

## The alerts

```
[1:1000001:1] LAB Sqlmap scanner User-Agent   [Web Application Attack] [Priority: 1]  198.51.100.66:44444 -> 192.0.2.5:80
[1:1000002:1] LAB SQL Injection attempt in URI [Web Application Attack] [Priority: 1]  198.51.100.66:44444 -> 192.0.2.5:80
[1:1000003:1] LAB TCP SYN port scan           [Attempted Information Leak] [Priority: 2]  198.51.100.66 -> 192.0.2.5
```

Three attacks caught in the packets, with the source, the target, and a priority. The two web attacks are priority 1 because a SQL injection against a live app is more urgent than reconnaissance.

## Reading an alert

An IDS alert has a fixed shape, worth knowing:
- `[1:1000001:1]` is generator, signature id (sid), revision. The sid identifies the rule.
- the message and classification say what it is and how bad
- the priority ranks it for triage
- the addresses show who attacked whom

That is enough to open a ticket: a web attack from `198.51.100.66` against the server on port 80.

## eve.json, the SIEM feed

Alongside `fast.log`, Suricata writes `eve.json`, a structured JSON log with far more detail (the full HTTP transaction, the flow, the matched rule). `eve.json` is what you ship into a SIEM, so this lab plugs straight into the Splunk and Elastic labs: Suricata detects at the network layer and the SIEM correlates it with everything else.

## What this maps to

- The port scan is **Reconnaissance, Active Scanning (MITRE ATT&CK T1595)**
- The SQL injection is **Initial Access, Exploit Public-Facing Application (T1190)**
- Writing IDS rules, running Suricata on a capture, and reading the alerts are core network security monitoring skills

## What I would do next

- Add the Emerging Threats open ruleset (`suricata-update`) so the capture is checked against thousands of community rules, not just mine
- Run Suricata live on an interface instead of a capture file
- Ship `eve.json` into Splunk or Elastic and build dashboards and correlation rules on it
- Add captures of more techniques: beaconing to a C2, data exfiltration over DNS

## Skills this shows

Running Suricata as a network IDS, writing custom detection rules (sticky buffers, thresholds, flow state), analysing a packet capture for attacks, reading and triaging IDS alerts, and understanding how network detection feeds a SIEM.

---

*The capture is crafted with documentation IP ranges. No real hosts or live traffic involved.*
