// Networking Mastery Tree Map - V3 Deep Explanations
// All content in Hinglish (simple Hindi-English mix)

// ---------------------------------------------------------------------------------------------------
// 1. DEEP DIVE DATA STRUCTURE (Multi-Level, Super Informative)
// ---------------------------------------------------------------------------------------------------

const DATA_DEEP_DIVE = {
  "name": "Networking Mastery Tree Map - Deep Dive V3",
  "children": [
    {
      "name": "Networking Fundamentals & Models",
      "children": [
        {
          "name": "OSI Reference Model (7 Layers)",
          "type": "topic",
          "short": "Network communication ko samajhne ke liye 7-layer theoretical framework.",
          "install": "n/a",
          "usage": "Troubleshooting mein use hota hai. Layer-by-layer protocols ko classify karta hai.",
          "children": [
            {
              "name": "Application (L7) & Presentation (L6)",
              "type": "sub_topic",
              "details": "User interaction aur data format/encryption. **HTTP, SMTP, FTP (L7), JPEG, TLS/SSL (L6)**.",
              "children": [
                {"name": "Layer 7 Protocols", "type": "detail", "usage": "Email, Web browsing, File transfer jaise services chalti hain.", "install": "HTTP, DNS, SMTP"},
                {"name": "Data Encryption/Decryption", "type": "detail", "usage": "Data ko secure format mein convert karna, Presentation Layer ka kaam.", "install": "SSL/TLS"}
              ]
            },
            {
              "name": "Transport Layer (L4)",
              "type": "sub_topic",
              "details": "End-to-end communication aur service port addressing. Data unit: **Segment**.",
              "children": [
                {"name": "TCP (Transmission Control Protocol)", "type": "protocol", "usage": "Reliable, connection-oriented data transfer. **Three-Way Handshake** use karta hai.", "install": "FTP, HTTP, SSH mein use hota hai"},
                {"name": "UDP (User Datagram Protocol)", "type": "protocol", "usage": "Fast, connectionless. Error checking kam karta hai. Streaming (Video/Voice) mein use hota hai.", "install": "DNS queries, VoIP, Gaming"}
              ]
            },
            {
              "name": "Network (L3) & Data Link (L2)",
              "type": "sub_topic",
              "details": "L3: Routing (IP address). L2: Frame switching (MAC address).",
              "children": [
                {"name": "IP Addressing & Routing", "type": "detail", "usage": "Logical addressing (IPv4/IPv6) aur best path selection (Routing). Device: Router.", "install": "ping, traceroute"},
                {"name": "MAC Addressing & Switching", "type": "detail", "usage": "Physical addressing aur local network (LAN) mein data transfer. Device: Switch.", "install": "arp -a (MAC dekho), ifconfig"}
              ]
            }
          ]
        },
        {
          "name": "IP Addressing & Subnetting",
          "type": "topic",
          "short": "Network devices ko unique logical addresses assign karna aur network ko optimize karna.",
          "install": "n/a",
          "usage": "Network design, security (ACLs), aur IP management.",
          "children": [
            {
              "name": "IPv4 vs IPv6",
              "type": "sub_topic",
              "details": "IPv4 (32-bit): Address shortage ki problem. IPv6 (128-bit): Massive address space, built-in security features.",
              "children": [
                {"name": "CIDR (Classless Inter-Domain Routing)", "type": "detail", "usage": "IPv4 addresses ko efficiently use karne ke liye. **Network mask /x notation**.", "install": "192.168.1.0/24"},
                {"name": "Private IP Ranges", "type": "detail", "usage": "Internet par route nahi hote. **10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16**.", "install": "Home/Office LANs mein use hote hain"}
              ]
            }
          ]
        }
      ]
    },

    {
      "name": "Routing & WAN Technologies",
      "children": [
        {
          "name": "Routing Protocols",
          "type": "topic",
          "short": "Routers ko sikhana ki packets ko kahan bhejna hai.",
          "install": "Cisco/Juniper commands",
          "usage": "Routing tables ko dynamically maintain karna.",
          "children": [
            {
              "name": "IGP (Interior Gateway Protocols)",
              "type": "sub_topic",
              "details": "Single Autonomous System (AS) ke andar routing.",
              "children": [
                {"name": "OSPF (Open Shortest Path First)", "type": "protocol", "usage": "Link-State protocol. Network topology ki poori map rakhta hai. Fast convergence.", "install": "Router (config-router) # router ospf 1"},
                {"name": "EIGRP (Enhanced Interior Gateway Routing Protocol)", "type": "protocol", "usage": "Cisco ka Hybrid protocol. Fast convergence aur kam bandwidth use karta hai.", "install": "Router (config-router) # router eigrp 10"}
              ]
            },
            {
              "name": "EGP (Exterior Gateway Protocol)",
              "type": "sub_topic",
              "details": "Do alag AS ke beech routing (Internet backbone).",
              "children": [
                {"name": "BGP (Border Gateway Protocol)", "type": "protocol", "usage": "Path-Vector protocol. Sabse zyada scalable. Internet par AS-to-AS routing ke liye mandatory.", "install": "Cisco # show ip bgp summary"}
              ]
            }
          ]
        },
        {
          "name": "Network Address Translation (NAT)",
          "type": "topic",
          "short": "Private IP ko Public IP mein convert karna.",
          "install": "Router configuration",
          "usage": "Multiple internal devices ko ek single public IP se Internet access dena. IPv4 shortage solve karna.",
          "children": [
            {
              "name": "PAT (Port Address Translation)",
              "type": "sub_topic",
              "details": "Dynamic NAT with Port numbers. Sabse common type (Home routers mein use hota hai).",
              "children": [
                {"name": "NAT Overload", "type": "detail", "usage": "Ek public IP ko multiple private IPs ke saath map karta hai, har device ko unique **Port Number** assign karke.", "install": "Router config: overload keyword use hota hai"}
              ]
            }
          ]
        }
      ]
    },

    {
      "name": "Network Security & Monitoring",
      "children": [
        {
          "name": "Firewalls and Security Controls",
          "type": "topic",
          "short": "Network traffic ko monitor aur control karna.",
          "install": "Physical appliance ya OS software",
          "usage": "Unauthorized access block karna aur network ko secure karna.",
          "children": [
            {
              "name": "Packet Filtering vs Stateful",
              "type": "sub_topic",
              "details": "Filtering: Sirf IP/Port dekhta hai. Stateful: Poore connection state ko track karta hai.",
              "children": [
                {"name": "Stateful Inspection Advantages", "type": "detail", "usage": "Zyada secure, kyonki yeh sirf valid replies ko hi allow karta hai. Context-aware security.", "install": "ACLs (Access Control Lists) se rules set hote hain"}
              ]
            },
            {
              "name": "VPN (Virtual Private Network)",
              "type": "sub_topic",
              "details": "Insecure public network (Internet) par secure private network banana.",
              "children": [
                {"name": "IPsec (Internet Protocol Security)", "type": "protocol", "usage": "VPN connections ke liye industry standard security protocol. Encryption, authentication, aur data integrity provide karta hai.", "install": "IKE, ESP, AH protocols use hote hain"}
              ]
            }
          ]
        },
        {
          "name": "Diagnostic Tools & Services",
          "type": "topic",
          "short": "Network health check karna aur issues diagnose karna.",
          "install": "OS built-in utilities",
          "usage": "Troubleshooting network connectivity aur performance problems.",
          "children": [
            {
              "name": "Ping & Traceroute",
              "type": "sub_topic",
              "details": "Connectivity test aur path trace karna.",
              "children": [
                {"name": "Ping (Packet Inter-Network Groper)", "type": "tool", "usage": "ICMP packets bhejkar dekhta hai ki remote host alive hai ya nahi. Latency check karta hai.", "install": "ping 8.8.8.8"},
                {"name": "Traceroute (Tracert)", "type": "tool", "usage": "Source se destination tak ka path aur har hop ki latency check karta hai.", "install": "traceroute google.com"}
              ]
            },
            {
              "name": "Netstat & Wireshark",
              "type": "sub_topic",
              "details": "Active connections aur deep packet analysis.",
              "children": [
                {"name": "Netstat (Network Statistics)", "type": "tool", "usage": "Active TCP connections, listening ports, aur routing table details dekhta hai.", "install": "netstat -an | findstr LISTENING"},
                {"name": "Wireshark", "type": "tool", "usage": "Packet Sniffer. Network traffic ko real-time mein capture aur analyze karta hai. Deep troubleshooting ke liye.", "install": "Install Wireshark software"}
              ]
            }
          ]
        }
      ]
    }
  ]
};
const DEEP_DATA_TOPIC = {
  name: "ARP Protocol and MITM Attacks",
  explanation: "ARP kya hai, kaise kaam karta hai, aur kaise attackers ARP spoofing/poisoning use karke MITM (Man-in-the-Middle) attacks karte hain — practical, detection aur mitigation sab kuch Hinglish mein.",
  details: "Extreme deep-dive map — protocol internals, attack chains, tools, detections, defenses, forensics aur OSINT use-cases.",
  children: [
    {
      name: "Level2: ARP Basics",
      explanation: "ARP ka fundamental concept: IP se MAC map karna local LAN ke andar.",
      details: "Address Resolution Protocol simple broadcast-request / unicast-reply mechanism pe chalti hai.",
      children: [
        {
          name: "Level3: ARP Message Types & Format",
          explanation: "ARP request, ARP reply, gratuitous ARP, proxy ARP ke formats aur fields.",
          details: "Hardware type, Protocol type, HLEN, PLEN, Operation, Sender MAC/IP, Target MAC/IP.",
          protocol_flow: "Host A -> Broadcast ARP Request (Who has IP X? Tell A). Host B -> Unicast ARP Reply (I am X, MAC Y).",
          vulnerability: "No authentication — kisi bhi host se spoofed reply accept ho sakta hai agar cache trust karta hai.",
          osint_use: "Local network scanning ke time gratuitous ARP se device presence detect kar sakte ho.",
          children: [
            {
              name: "Level4: Gratuitous ARP & Proxy ARP",
              explanation: "Gratuitous ARP: host apna IP announce karta; Proxy ARP: router/host doosre host ke liye ARP answer karta.",
              details: "Gratuitous ARP se IP conflicts detect hote; Proxy ARP NAT/hairpin setups me use hota.",
              security_risk: "Gratuitous ARP spoofing se ARP cache overwrite karwa ke traffic divert ho sakta.",
              defense: "Disable gratuitous ARP acceptance on critical hosts, use static mappings for infrastructure devices.",
              children: [
                {
                  name: "Level5: Implementation Notes & Best Practices",
                  explanation: "Switch aur host level settings jo gratuitous/proxy ARP se related hone chahiye.",
                  details: "Switches pe DHCP snooping + Dynamic ARP Inspection (DAI), hosts pe static ARP for gateways.",
                  tool: "Switch features: Cisco DAI, Juniper ARP-protection; Host: arp -s static entries.",
                  defense: "Network-wide: enable DHCP Snooping, DAI, IP-MAC binding; Host: disable ARP learning for critical interfaces.",
                  osint_use: "Infosec red-team: gratuitous ARP dekh ke active hosts enumerate kar sakte hain (lab/testing only)."
                }
              ]
            }
          ]
        },
        {
          name: "Level3: ARP Caching Behavior",
          explanation: "ARP cache entries — dynamic vs static, cache timeout, entry replacement behavior.",
          details: "OS alag timeouts use karte hain; stale entries replace hona possible hai via new replies.",
          vulnerability: "Cache replacement race: spoofed reply can overwrite legitimate entry if timing sahi ho.",
          defense: "Use static entries for gateways, enable OS-level ARP protections where available.",
          children: [
            {
              name: "Level4: OS-specific Behavior",
              explanation: "Linux, Windows, macOS ARP cache management differences aur tweaks.",
              details: "Linux: /proc/sys/net/ipv4/conf/*/arp_ignore & arp_announce tunables; Windows: registry ARP tweaks.",
              tool: "sysctl settings, registry tweaks, ip neigh commands.",
              defense: "Tune arp_ignore/arp_announce; restrict gratuitous ARP acceptance on servers.",
              children: [
                {
                  name: "Level5: Hardening Commands & Examples",
                  explanation: "Practical commands to harden host ARP behavior (Hinglish comments).",
                  details: "Linux example: sysctl -w net.ipv4.conf.all.arp_ignore=1; sysctl -w net.ipv4.conf.all.arp_announce=2",
                  tool: "ip neigh show; arp -n; netsh interface ip show neighbors (Windows).",
                  defense: "Deploy via config management (Ansible) across critical fleet to avoid config drift.",
                  osint_use: "Hardening state detect karna se pata chalta kaunse hosts prone hain (for defensive inventory)."
                }
              ]
            }
          ]
        }
      ]
    },
    {
      name: "Level2: ARP Protocol Mechanics Deep Dive",
      explanation: "Link-layer pe ARP frame ka traversal, promiscuous interfaces, switching behavior aur timing issues.",
      details: "Ethernet frame structure, broadcast domain effects, switch CAM table interactions with spoofed MACs.",
      children: [
        {
          name: "Level3: Frame Lifecycle & Switch Interaction",
          explanation: "Ethernet broadcast se ARP request sabko milega; unicast reply ko switch CAM table use karke forward karta.",
          details: "Switch learns port<->MAC mapping; attacker can poison CAM by sending frames with spoofed MACs.",
          protocol_flow: "Attacker sends ARP Reply with fake MAC -> Switch updates CAM -> traffic for victim MAC sent to attacker port.",
          security_risk: "CAM table poisoning leads to traffic interception or DoS (flooding).",
          tool: "Switch show mac address-table, tcpdump -e to inspect Ethernet headers.",
          children: [
            {
              name: "Level4: Timing & Race Conditions",
              explanation: "ARP reply arrival time vs legitimate reply — attacker must respond before legit to win cache.",
              details: "Fast repeated spoofed replies maintain poisoned state; TTL/timeouts decide window.",
              vulnerability: "Race-win attacks: attacker continuously floods spoofed replies to sustain MITM.",
              defense: "Rate-limit ARP replies, enable DAI on switches to validate MAC-IP bindings.",
              children: [
                {
                  name: "Level5: Practical Attack Window Analysis",
                  explanation: "How long a poisoned entry stays and how to calculate attack persistence.",
                  details: "Measure OS ARP timeout (e.g., 60s), attacker must refresh before expiry; account for network latency.",
                  protocol_flow: "Attacker: periodic ARP replies every (timeout/2) seconds -> keeps ARP cache poisoned.",
                  tool: "Scripts: arpspoof, ettercap, arping; defensive: tcpdump, tshark to observe refreshes.",
                  security_risk: "Persistent MITM leading to prolonged exfiltration or credential capture.",
                  defense: "Monitor for frequent ARP replies for same IP from multiple MACs; alert on suspicious frequency.",
                  osint_use: "Red team measures attack window to minimize detection during engagement planning."
                }
              ]
            }
          ]
        }
      ]
    },
    {
      name: "Level2: ARP MITM Attack Techniques",
      explanation: "Real-world techniques attackers use: ARP spoofing/poisoning, ARP cache poisoning combined with ICMP/TCP hijack, proxying, SSL stripping etc.",
      details: "Attack chains from initial access to traffic interception, session hijack and credential capture.",
      children: [
        {
          name: "Level3: ARP Spoofing (Classic MITM)",
          explanation: "Attacker poisons victim and gateway ARP caches to position self between them.",
          protocol_flow: "Attacker -> send ARP reply to Victim mapping Gateway IP -> Attacker MAC. Attacker -> send ARP reply to Gateway mapping Victim IP -> Attacker MAC.",
          security_risk: "All victim <-> internet traffic flows via attacker: sniffing, modification, injection possible.",
          tool: "arpspoof, bettercap, ettercap, arpcap scripts for automated poisoning.",
          vulnerability: "No ARP authentication; hosts accept unsolicited ARP replies by default.",
          osint_use: "Local network enumeration to find high-value targets (e.g., servers, gateway) before poisoning.",
          children: [
            {
              name: "Level4: ARP Proxying & Forwarding Techniques",
              explanation: "Attacker sets up IP forwarding and optionally NAT to transparently proxy traffic.",
              details: "Enable sysctl net.ipv4.ip_forward=1; use iptables to NAT/redirect traffic for manipulation.",
              protocol_flow: "Victim -> Attacker (forwarded) -> Gateway. Attacker can log, modify, inject before forwarding.",
              tool: "iptables, mitmproxy, sslstrip (legacy), tcpdump for capture.",
              defense: "Egress filtering, endpoint TLS validation, HSTS to prevent SSL stripping.",
              children: [
                {
                  name: "Level5: Payload Manipulation & Session Hijack",
                  explanation: "How attacker modifies responses or injects payloads to capture creds or persistent access.",
                  details: "Forms injection, JS replacement, credential sniffer for HTTP basic auth, cookie theft if not secure.",
                  protocol_flow: "Attacker proxies HTTP -> inject JS to exfiltrate cookies -> send to C2.",
                  tool: "mitmproxy for scriptable manipulation; Burp as proxy for manual inspection.",
                  security_risk: "Credential theft, session takeover, malware distribution inside LAN.",
                  defense: "Use HTTPS with certificate pinning, HSTS, secure cookies, and monitoring for modified content hashes.",
                  osint_use: "During red-team ops, attacker maps which services use plaintext HTTP to target manipulation."
                }
              ]
            }
          ]
        },
        {
          name: "Level3: ARP Cache Poisoning at Scale (Network-wide)",
          explanation: "Mass poisoning across VLAN/segment to intercept multiple hosts or segment-wide traffic.",
          details: "Attacker uses amplified ARP reply floods, or takes control of a switch-port with promiscuous/sniffing mode.",
          protocol_flow: "Spoofed ARP replies emitted to many hosts; compromised switch CAM entries cause widespread redirection.",
          tool: "Bettercap, Scapy-based custom poisoners with multiprocessing, mac flooding tools.",
          security_risk: "Large-scale data exposure, lateral movement facilitation.",
          vulnerability: "Unsegmented broadcast domains increase impact; unmanaged switches lack DAI.",
          defense: "VLAN segmentation, private VLANs, port-security, MAC sticky and CAM limiting.",
          children: [
            {
              name: "Level4: Switch-level Countermeasures",
              explanation: "Configure port-security, CAM limits, storm-control and Dynamic ARP Inspection.",
              details: "Example: Cisco switch: switchport port-security maximum 2; ip arp inspection trust/untrust.",
              tool: "Switch CLI (Cisco/Juniper), NAC appliances, 802.1X for port control.",
              defense: "Combine port-security + 802.1X + DAI to block mass poisoning.",
              children: [
                {
                  name: "Level5: Operational Playbook for Mitigation",
                  explanation: "Step-by-step ops to detect and contain mass ARP poisoning in production.",
                  details: "1) Isolate affected switch port, 2) clear CAM table, 3) enable DAI+DHCP snooping, 4) check host ARP caches, 5) rotate credentials if exfiltration suspected.",
                  tool: "syslog + SIEM alerts for ARP anomalies, NAC logs, switch logs.",
                  defense: "Automated runbooks in SOAR to triage and remediate poisoning quickly.",
                  osint_use: "Post-incident: analyze PCAPs to map attacker movement and timeline for threat intelligence."
                }
              ]
            }
          ]
        }
      ]
    },
    {
      name: "Level2: Detection, Monitoring & Forensics",
      explanation: "How to detect ARP-MITM in real time, forensically analyze captures, and create alerts (SIEM).",
      details: "Both network-based and host-based detection techniques with sample queries and detection signatures.",
      children: [
        {
          name: "Level3: Network Detection Rules",
          explanation: "Signatures and heuristics: duplicate IP mapped to multiple MACs, high frequency ARP replies, gratuitous ARP spikes.",
          details: "Write IDS rules (Suricata/Snort) and SIEM searches to catch anomalies.",
          protocol_flow: "Monitor ARP replies: if same IP seen from multiple MACs OR same MAC answers for many IPs -> suspicious.",
          tool: "Suricata, Snort, Zeek (Bro), ELK stack for correlation, tshark/tcpdump for capture.",
          security_risk: "False negatives if attacker throttles spoofing; false positives with legitimate failovers.",
          defense: "Tune thresholds, combine with DHCP logs and switch CAM table correlation.",
          children: [
            {
              name: "Level4: Example Detection Signatures",
              explanation: "Practical IDS rules and SIEM queries (Hinglish explanation + examples).",
              details: "Suricata rule idea: alert on ARP reply where sender IP != owner by DHCP lease, or multiple MACs for one IP.",
              tool: "Suricata rule, Zeek script to track IP->MAC mappings over time, ELK queries to flag flapping.",
              defense: "Create alert playbooks: verify DHCP leases, check switch mac-table, contact user.",
              children: [
                {
                  name: "Level5: Forensic Workflow & Evidence Collection",
                  explanation: "Collect PCAPs, switch CAM snapshots, host ARP caches, DHCP server logs; preserve chain-of-custody.",
                  details: "Commands: tcpdump -i any arp -w arp_mitm.pcap; show mac address-table; arp -n; dhcp logs timestamped.",
                  tool: "tshark for filtering, Wireshark for analysis, SiLK/nfdump for netflow correlation.",
                  defense: "Use centralized PCAP/flow collectors and immutable storage for evidence.",
                  osint_use: "Extract indicators (attacker MACs, IPs, timestamps) to enrich internal threat intel and blocklists."
                }
              ]
            }
          ]
        },
        {
          name: "Level3: Host-based Detection",
          explanation: "Endpoint sensors can detect ARP cache changes, unexpected gateway MAC changes, or new default gateway.",
          details: "Host EDR rules that alert when gateway MAC changes or when gratuitous ARP received from unknown NIC.",
          tool: "OSSEC, Wazuh, EDR custom rules, local scripts to monitor `ip neigh` / `arp -n`.",
          defense: "Host hardening + alerting to notify SOC about possible MITM attempts.",
          children: [
            {
              name: "Level4: Example Host Monitors & Scripts",
              explanation: "Lightweight scripts to run as service to detect gateway MAC change and notify.",
              details: "Cron job or systemd service that checks default gateway MAC every 30s and compares to baseline.",
              tool: "bash/python script sample, integration with syslog for SIEM ingestion.",
              defense: "Automated trigger: on change, disable networking on host and escalate to SOC.",
              children: [
                {
                  name: "Level5: Playbook for SOC Triage on Host Alert",
                  explanation: "SOC steps after host-based ARP alert: isolate host, capture memory/pcap, query switch, check for lateral movement.",
                  details: "Record all findings in ticket, preserve timeline, rotate credentials if sensitive traffic suspected.",
                  tool: "EDR console, remote forensics tools (osquery), centralized logging.",
                  defense: "Integrate host alerts with network detection to reduce false positives and speed response."
                }
              ]
            }
          ]
        }
      ]
    },
    {
      name: "Level2: Defenses, Hardening & Mitigation",
      explanation: "Network and host-level mitigations from basic to advanced (DAI, 802.1X, static mapping, encryption).",
      details: "Prevention, detection, containment and recovery strategies in layered defenses.",
      children: [
        {
          name: "Level3: Network Layer Protections",
          explanation: "Switch features: DHCP Snooping, Dynamic ARP Inspection (DAI), Port Security, 802.1X NAC.",
          details: "DHCP Snooping builds IP-MAC binding table used by DAI to validate ARP replies.",
          defense: "Enable DHCP Snooping + DAI on access switches; use port-security with MAC sticky and limits.",
          tool: "Switch configuration CLIs (Cisco, Aruba, Juniper), NAC solutions.",
          children: [
            {
              name: "Level4: Example Config Snippets",
              explanation: "Concrete config examples (Hinglish comments) for Cisco-like switches.",
              details: "configure terminal\n ip dhcp snooping\n ip dhcp snooping vlan 10\n interface Gig1/0/1\n  switchport mode access\n  ip dhcp snooping trust (for uplink)\n  ip arp inspection trust (uplink)\n",
              tool: "Switch CLI, automation via Ansible to push config at scale.",
              defense: "Automate enforcement and audit configs regularly to avoid misconfigurations.",
              children: [
                {
                  name: "Level5: Validation & Testing Procedures",
                  explanation: "How to test that protections work without causing outages (lab first).",
                  details: "Test plan: 1) lab simulate ARP spoofing, 2) verify DAI drops spoofed packets, 3) monitor logs for drops.",
                  tool: "Test tools: Scapy scripts to craft ARP replies, ettercap in test VLAN.",
                  defense: "Use staged rollout, monitor for false positives and tune thresholds."
                }
              ]
            }
          ]
        },
        {
          name: "Level3: Application & Transport Layer Mitigations",
          explanation: "Even if ARP MITM occurs, TLS and secure auth reduce impact.",
          details: "Use HTTPS everywhere, certificate pinning, HSTS, secure cookies, MFA to protect sessions.",
          defense: "Enforce TLS, use mTLS where possible, deploy HTTP Strict Transport Security.",
          children: [
            {
              name: "Level4: TLS Best Practices",
              explanation: "Prevent SSL stripping and payload manipulation even under MITM conditions.",
              details: "HSTS preloading, enable TLS 1.2/1.3 only, disable weak ciphers, certificate monitoring.",
              tool: "Let's Encrypt automation, Cert-Manager, Observability for certificate changes.",
              defense: "Automated detection of certificate changes and alerts for unexpected certs (possible MITM).",
              children: [
                {
                  name: "Level5: Incident Response for Suspected MITM",
                  explanation: "Containment steps when MITM suspected despite TLS: rotate keys, reprovision certs, forensic capture.",
                  details: "Revoke compromised certs if private keys suspected, reissue, check CT logs for anomalies.",
                  tool: "Certificate Transparency logs, OCSP/CRL checks, key management systems.",
                  defense: "Pre-established incident runbooks for crypto key compromise scenarios."
                }
              ]
            }
          ]
        }
      ]
    },
    {
      name: "Level2: OSINT, Red Teaming & Responsible Use",
      explanation: "How ARP techniques are used in red-team/OSINT labs (ethical), and how defenders can use OSINT to map network risks.",
      details: "Always legal and authorized testing only. Use findings to remediate, not exploit.",
      children: [
        {
          name: "Level3: Reconnaissance & Mapping",
          explanation: "Local OSINT: map active hosts, gateways, services using ARP/gratuitous ARP and passive sniffing.",
          details: "Use safe scans to list IP->MAC, identify high-value targets (servers, printers, gateways).",
          tool: "arp-scan, netdiscover, nmap -sn, passive pcap analysis.",
          osint_use: "Create asset inventory and identify unsegmented broadcast domains that increase ARP attack surface.",
          children: [
            {
              name: "Level4: Red Team Planning",
              explanation: "Plan MITM with minimal footprint: timing, selective targets, exfil channels, opsec.",
              details: "Prefer short windows, exfil via encrypted channels to C2, avoid noisy broadcasts to reduce detection.",
              tool: "Bettercap scripts, Scapy for custom stealth poisoning, covert channels (DNS/HTTPS).",
              security_risk: "Unethical misuse: mass data capture, privacy breach — always require written authorization.",
              children: [
                {
                  name: "Level5: Ethical Reporting Template",
                  explanation: "How to report findings to stakeholders responsibly (Hinglish template).",
                  details: "Report should include: summary, affected hosts, PoC capture, timeline, remediation steps, risk classification.",
                  osint_use: "Include indicators (MACs, timestamps) for defenders to block and for threat intel sharing.",
                  defense: "Follow coordinated disclosure, provide mitigation guidance and support patching/hardening."
                }
              ]
            }
          ]
        },
        {
          name: "Level3: Threat Intelligence & IOC Sharing",
          explanation: "Share relevant indicators of compromise (MACs, attacker IPs, tooling fingerprints) with SOC and peers.",
          details: "Use STIX/TAXII or internal intel platforms to share IOCs and detection recipes.",
          osint_use: "Enrich community intel: e.g., unusual vendor OUIs used by attacker NICs may be part of campaign profiling.",
          children: [
            {
              name: "Level4: Building Detection Signatures from Red Team PoC",
              explanation: "Convert PoC behaviors into SIEM rules and IDS signatures.",
              details: "Examples: rule when one IP mapped to >1 MAC in 60s, or more than N gratuitous ARPs per minute.",
              tool: "Elastic SIEM, Splunk, Suricata rule sets.",
              children: [
                {
                  name: "Level5: Continuous Improvement Cycle",
                  explanation: "Test -> detect -> tune -> deploy: keep detection updated as attacker TTPs evolve.",
                  details: "Run periodic red-team drills, update signatures, measure detection and mean-time-to-remediate (MTTR).",
                  defense: "Integrate lessons into training, SOC runbooks and automated containment playbooks."
                }
              ]
            }
          ]
        }
      ]
    }
  ]
};


// ---------------------------------------------------------------------------------------------------
// 2. D3.js LOGIC AND UTILITIES (Original logic maintained, DATA replaced)
// ---------------------------------------------------------------------------------------------------

// D3.js setup for the tree map
let i = 0, duration = 750, root;
const margin = { top: 20, right: 100, bottom: 20, left: 100 };
const width = 1200 - margin.right - margin.left;
const height = 800 - margin.top - margin.bottom;

const svg = d3.select("#treeSvg")
  .attr("viewBox", `0 0 ${width + margin.right + margin.left} ${height + margin.top + margin.bottom}`)
  .append("g")
  .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

const tree = d3.tree().size([height, width]);

// Zoom behavior setup
const zoom = d3.zoom()
  .scaleExtent([0.1, 4])
  .on("zoom", (event) => {
    svg.attr("transform", event.transform);
  });

d3.select("#treeSvg").call(zoom);

// Convert the flat data to a hierarchical structure
root = d3.hierarchy(DATA_DEEP_DIVE, d => d.children);
root.x0 = height / 2;
root.y0 = 0;

// Store all nodes in a flat list for searching
const flatList = [];
root.each(d => {
  flatList.push(d.data);
  // Initially collapse all children below the top level
  if (d.depth >= 1) {
    d._children = d.children; // Store children in _children
    d.children = null;       // Collapse them
  }
});
// Re-expand the top level
root.children.forEach(c=>{ c.children = c._children || c.children; c._children = null;});


// Utility function to show details in the right panel
const panelTitle = document.getElementById('panelTitle');
const panelShort = document.getElementById('panelShort');
const panelInstall = document.getElementById('panelInstall');
const panelUsage = document.getElementById('panelUsage');
const panelUse = document.getElementById('panelUse');
const explainList = document.getElementById('explainList');

function showDetails(d) {
  panelTitle.textContent = d.name;
  panelShort.textContent = d.short || d.details || "No short summary available.";
  panelInstall.textContent = d.install || "n/a (Not a command/tool)";
  panelUsage.textContent = d.usage || "Select a leaf node for usage example.";
  panelUse.textContent = d.details || d.explanation || "No deep explanation available. Explore further branches.";

  // Highlight the corresponding item in the explanations list
  const activeItems = explainList.querySelectorAll('.item');
  activeItems.forEach(item => item.classList.remove('active'));
  const activeItem = explainList.querySelector(`.item[data-name="${d.name}"]`);
  if (activeItem) {
    activeItem.classList.add('active');
    activeItem.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  // Highlight the node on the tree
  d3.selectAll(".node").classed("highlight", false).classed("dimmed", false);
  d3.selectAll(".link").classed("highlight", false);

  let current = d;
  while(current) {
    d3.select(`#node-${current.id || i}`).classed("highlight", true);
    d3.select(`#link-${current.parent?.id}`).classed("highlight", true);
    current = current.parent;
  }
}

// Click event handler for nodes
function click(event, d) {
  if (d.children) {
    d._children = d.children;
    d.children = null;
  } else {
    d.children = d._children;
    d._children = null;
  }
  update(d);
  showDetails(d.data);
}

// Function to center the view on a specific node
function centerNode(source) {
  const scale = 1.0;
  const x = -source.y * scale + width / 2;
  const y = -source.x * scale + height / 2;
  d3.select("#treeSvg").transition()
    .duration(duration)
    .call(zoom.transform, d3.zoomIdentity.translate(x, y).scale(scale));
}

// Main update function
function update(source) {
  const treeData = tree(root);

  // Compute the new tree layout
  const nodes = treeData.descendants();
  const links = treeData.descendants().slice(1);

  // Normalize for fixed-depth
  nodes.forEach(d => { d.y = d.depth * 180; });

  // 1. Update the nodes
  const node = svg.selectAll('g.node')
    .data(nodes, d => d.id || (d.id = ++i));

  // Enter any new nodes at the parent's previous position
  const nodeEnter = node.enter().append('g')
    .attr('class', 'node')
    .attr("id", d => `node-${d.id}`)
    .attr("transform", d => "translate(" + source.y0 + "," + source.x0 + ")")
    .on('click', click)
    .on('mouseover', (event, d) => {
      d3.select(event.currentTarget).select('text').style('opacity', 1);
    })
    .on('mouseout', (event, d) => {
      // Keep opacity high only if the node is a leaf (no children or collapsed children)
      if (d.children || d._children) {
        d3.select(event.currentTarget).select('text').style('opacity', 0.8);
      }
    });

  // Add Circle for the nodes
  nodeEnter.append('circle')
    .attr('r', 1e-6)
    .style("fill", d => d._children ? "#4da6ff" : "#fff");

  // Add text for the nodes
  nodeEnter.append('text')
    .attr("dy", ".35em")
    .attr("x", d => d.children || d._children ? -13 : 13)
    .attr("text-anchor", d => d.children || d._children ? "end" : "start")
    .text(d => d.data.name)
    .style('fill', '#cfe7ff')
    .style('font-weight', '500')
    .style('opacity', 1.0); // Always visible now

  // Update the transition for nodes
  const nodeUpdate = nodeEnter.merge(node);

  // Transition to the new position
  nodeUpdate.transition()
    .duration(duration)
    .attr("transform", d => "translate(" + d.y + "," + d.x + ")");

  // Update the node attributes and style
  nodeUpdate.select('circle')
    .attr('r', 8)
    .style("fill", d => d._children ? "#4da6ff" : "#071126")
    .attr('cursor', 'pointer');

  // Transition exiting nodes to the parent's new position
  const nodeExit = node.exit().transition()
    .duration(duration)
    .attr("transform", d => "translate(" + source.y + "," + source.x + ")")
    .remove();

  nodeExit.select('circle')
    .attr('r', 1e-6);

  nodeExit.select('text')
    .style('fill-opacity', 1e-6);

  // 2. Update the links
  const link = svg.selectAll('path.link')
    .data(links, d => d.id);

  // Enter any new links at the parent's previous position
  const linkEnter = link.enter().insert('path', "g")
    .attr("class", "link")
    .attr("id", d => `link-${d.id}`)
    .attr('d', d => {
      const o = { x: source.x0, y: source.y0 };
      return diagonal(o, o);
    });

  // Update the transition for links
  const linkUpdate = linkEnter.merge(link);

  // Transition back to the parent's new position
  linkUpdate.transition()
    .duration(duration)
    .attr('d', d => diagonal(d, d.parent));

  // Transition exiting links to the parent's new position
  link.exit().transition()
    .duration(duration)
    .attr('d', d => {
      const o = { x: source.x, y: source.y };
      return diagonal(o, o);
    })
    .remove();

  // Store the old positions for transition
  nodes.forEach(d => {
    d.x0 = d.x;
    d.y0 = d.y;
  });

  // Diagonal function to draw the curved links
  function diagonal(s, d) {
    return `M ${s.y} ${s.x}
      C ${(s.y + d.y) / 2} ${s.x},
        ${(s.y + d.y) / 2} ${d.x},
        ${d.y} ${d.x}`;
  }
}

// ---------------------------------------------------------------------------------------------------
// 3. UI AND EVENT HANDLERS
// ---------------------------------------------------------------------------------------------------

const searchInput = document.getElementById('search');

// Search and Filter functionality
searchInput.addEventListener("input", (e) => {
  const query = e.target.value.trim().toLowerCase();
  if (!query) {
    d3.selectAll(".node").classed("dimmed", false).classed("highlight", false);
    d3.selectAll(".link").classed("highlight", false);
    return;
  }

  // Find all matching nodes
  const matches = [];
  root.each(d => {
    if (d.data.name.toLowerCase().includes(query) || (d.data.short && d.data.short.toLowerCase().includes(query))) {
      matches.push(d);
    }
  });

  // Dim non-matching nodes and highlight matches and their path
  d3.selectAll(".node").classed("dimmed", true).classed("highlight", false);
  d3.selectAll(".link").classed("highlight", false);

  matches.forEach(match => {
    let current = match;
    while (current) {
      d3.select(`#node-${current.id}`).classed("dimmed", false).classed("highlight", true);
      if (current.parent) {
        d3.select(`#link-${current.id}`).classed("highlight", true);
      }
      current = current.parent;
    }
  });

  // Center the first match if available
  if (matches.length > 0) {
    centerNode(matches[0]);
  }
});

// Expand/Collapse All
function toggleAll(d) {
  if (d.children) {
    d.children.forEach(toggleAll);
    d._children = d.children;
    d.children = null;
  } else if (d._children) {
    d._children.forEach(toggleAll);
    d.children = d._children;
    d._children = null;
  }
}

document.getElementById('expandAll').addEventListener('click', () => {
  root.each(d => {
    d.children = d._children || d.children;
    d._children = null;
  });
  update(root);
  centerNode(root);
});

document.getElementById('collapseAll').addEventListener('click', () => {
  root.each(d => {
    if (d.depth > 0 && d.children) {
      d._children = d.children;
      d.children = null;
    }
  });
  // Keep the first level expanded
  root.children.forEach(c => { c.children = c._children || c.children; c._children = null; });
  update(root);
  centerNode(root);
});

// Theme Toggle
document.getElementById('toggleTheme').addEventListener('click', () => {
  document.body.classList.toggle('theme-dark');
  document.body.classList.toggle('theme-light');
});

// Export JSON (for the user's convenience)
document.getElementById('exportJson').addEventListener('click', () => {
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(DATA_DEEP_DIVE, null, 2));
  const downloadAnchorNode = document.createElement('a');
  downloadAnchorNode.setAttribute("href", dataStr);
  downloadAnchorNode.setAttribute("download", "networking_data_deep_dive.json");
  document.body.appendChild(downloadAnchorNode);
  downloadAnchorNode.click();
  downloadAnchorNode.remove();
});


// ---------------------------------------------------------------------------------------------------
// 4. LEARN PATH AND EXPLANATION LIST
// ---------------------------------------------------------------------------------------------------

// Mock Learn Paths based on the new deep structure (adjusting original logic)
const beginner = ["OSI Reference Model (7 Layers)", "IP Addressing & Subnetting", "Ping (Packet Inter-Network Groper)"];
const intermediate = ["Routing Protocols", "NAT (Port Address Translation)", "Stateful Inspection Advantages"];
const advanced = ["BGP (Border Gateway Protocol)", "EIGRP (Enhanced Interior Gateway Routing Protocol)", "IPsec (Internet Protocol Security)"];

function populatePath(id, path) {
  const ol = document.getElementById(id);
  path.forEach(name => {
    const li = document.createElement('li');
    li.textContent = name;
    li.classList.add('item');
    li.onclick = () => {
      // Find the corresponding node and center it
      let foundNode = null;
      root.each(d => {
        if (d.data.name === name) foundNode = d;
      });
      if (foundNode) {
        // Expand path to the found node first
        let current = foundNode;
        const nodesToExpand = [];
        while(current.parent) {
          nodesToExpand.push(current.parent);
          current = current.parent;
        }
        nodesToExpand.reverse().forEach(n => {
          if (n._children) {
            n.children = n._children;
            n._children = null;
          }
        });
        update(foundNode.parent || root);
        centerNode(foundNode);
        showDetails(foundNode.data);
      }
    };
    ol.appendChild(li);
  });
}

function populateExplanationList(data) {
  const allNodes = [];
  function traverse(node) {
    if (node.children) {
      node.children.forEach(traverse);
    }
    if (node.details || node.short) {
      allNodes.push(node);
    }
  }
  traverse(data);

  // Clear existing list
  explainList.innerHTML = '';

  allNodes.forEach(d => {
    const div = document.createElement('div');
    div.classList.add('item');
    div.setAttribute('data-name', d.name);
    div.innerHTML = `<strong>${d.name}</strong>: ${d.short || d.details}`;
    div.onclick = () => {
      // Find the corresponding node in the tree structure and show its details
      let foundNode = null;
      root.each(n => {
        if (n.data.name === d.name) foundNode = n;
      });
      if (foundNode) {
        // Logic to expand path added for better UX
        let current = foundNode;
        const nodesToExpand = [];
        while(current.parent) {
          nodesToExpand.push(current.parent);
          current = current.parent;
        }
        nodesToExpand.reverse().forEach(n => {
          if (n._children) {
            n.children = n._children;
            n._children = null;
          }
        });
        update(foundNode.parent || root);
        centerNode(foundNode);
        showDetails(foundNode.data);
      }
    };
    explainList.appendChild(div);
  });
}

populatePath("pathBeginner", beginner);
populatePath("pathIntermediate", intermediate);
populatePath("pathAdvanced", advanced);
populateExplanationList(DATA_DEEP_DIVE);


// ---------------------------------------------------------------------------------------------------
// 5. INITIALIZATION
// ---------------------------------------------------------------------------------------------------

// initial expand top-level
root.children.forEach(c => { c.children = c._children || c.children; c._children = null; });
update(root);

// accessibility: keyboard search enter focuses first match
searchInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    const q = searchInput.value.trim().toLowerCase();
    if (!q) return;
    const foundData = flatList.find(n => n.name.toLowerCase().includes(q));
    if (foundData) {
      let foundNode = null;
      root.each(d => {
        if (d.data.name === foundData.name) foundNode = d;
      });
      if (foundNode) centerNode(foundNode);
      showDetails(foundData);
    }
  }
});

// center root on load and apply initial zoom
setTimeout(() => {
  // zoom to show central area
  d3.select("#treeSvg").call(zoom.transform, d3.zoomIdentity.translate(80, 20).scale(1));
}, 150);


// Simple CSS for tooltip and active explanation (appended to head)
const style = document.createElement('style');
style.innerHTML = `
.tt{box-shadow:0 10px 30px rgba(0,0,0,0.6);border-radius:8px}
.explainList .item.active{background:linear-gradient(90deg, rgba(77,166,255,0.06), transparent)}
.node circle{filter: drop-shadow(0 6px 12px rgba(77,166,255,0.06));}
.node:hover circle{stroke-width:2.6px;filter: drop-shadow(0 10px 20px rgba(77,166,255,0.16));}
`;
document.head.appendChild(style);
