// Networking Mastery Tree Map - V3 Deep Explanations (ARP/MITM Deep Dive Integrated)
// All content in Hinglish (simple Hindi-English mix)

// ---------------------------------------------------------------------------------------------------
// 1. DEEP DIVE DATA STRUCTURE (Multi-Level, Super Informative)
// *** NOTE: The DEEP_DATA_TOPIC has been merged into DATA_DEEP_DIVE ***
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
        // --- START OF INTEGRATED DEEP_DATA_TOPIC ---
        {
          name: "ARP Protocol and MITM Attacks",
          type: "topic",
          short: "ARP kya hai, kaise kaam karta hai, aur kaise attackers ARP spoofing/poisoning use karke MITM (Man-in-the-Middle) attacks karte hain — practical, detection aur mitigation sab kuch Hinglish mein.",
          details: "Extreme deep-dive map — protocol internals, attack chains, tools, detections, defenses, forensics aur OSINT use-cases.",
          children: [
            {
              name: "Level2: ARP Basics",
              type: "sub_topic",
              explanation: "ARP ka fundamental concept: IP se MAC map karna local LAN ke andar.",
              details: "Address Resolution Protocol simple broadcast-request / unicast-reply mechanism pe chalti hai.",
              children: [
                {
                  name: "Level3: ARP Message Types & Format",
                  type: "detail",
                  explanation: "ARP request, ARP reply, gratuitous ARP, proxy ARP ke formats aur fields.",
                  details: "Hardware type, Protocol type, HLEN, PLEN, Operation, Sender MAC/IP, Target MAC/IP.",
                  children: [
                    {
                      name: "Level4: Gratuitous ARP & Proxy ARP",
                      type: "detail",
                      explanation: "Gratuitous ARP: host apna IP announce karta; Proxy ARP: router/host doosre host ke liye ARP answer karta.",
                      children: [
                        {
                          name: "Level5: Implementation Notes & Best Practices",
                          type: "detail",
                          explanation: "Switch aur host level settings jo gratuitous/proxy ARP se related hone chahiye.",
                        }
                      ]
                    }
                  ]
                },
                {
                  name: "Level3: ARP Caching Behavior",
                  type: "detail",
                  explanation: "ARP cache entries — dynamic vs static, cache timeout, entry replacement behavior.",
                  children: [
                    {
                      name: "Level4: OS-specific Behavior",
                      type: "detail",
                      explanation: "Linux, Windows, macOS ARP cache management differences aur tweaks.",
                      children: [
                        {
                          name: "Level5: Hardening Commands & Examples",
                          type: "detail",
                          explanation: "Practical commands to harden host ARP behavior (Hinglish comments).",
                        }
                      ]
                    }
                  ]
                }
              ]
            },
            {
              name: "Level2: ARP Protocol Mechanics Deep Dive",
              type: "sub_topic",
              explanation: "Link-layer pe ARP frame ka traversal, promiscuous interfaces, switching behavior aur timing issues.",
              details: "Ethernet frame structure, broadcast domain effects, switch CAM table interactions with spoofed MACs.",
              children: [
                {
                  name: "Level3: Frame Lifecycle & Switch Interaction",
                  type: "detail",
                  explanation: "Ethernet broadcast se ARP request sabko milega; unicast reply ko switch CAM table use karke forward karta.",
                  children: [
                    {
                      name: "Level4: Timing & Race Conditions",
                      type: "detail",
                      explanation: "ARP reply arrival time vs legitimate reply — attacker must respond before legit to win cache.",
                      children: [
                        {
                          name: "Level5: Practical Attack Window Analysis",
                          type: "detail",
                          explanation: "How long a poisoned entry stays and how to calculate attack persistence.",
                        }
                      ]
                    }
                  ]
                }
              ]
            },
            {
              name: "Level2: ARP MITM Attack Techniques",
              type: "sub_topic",
              explanation: "Real-world techniques attackers use: ARP spoofing/poisoning, ARP cache poisoning combined with ICMP/TCP hijack, proxying, SSL stripping etc.",
              details: "Attack chains from initial access to traffic interception, session hijack and credential capture.",
              children: [
                {
                  name: "Level3: ARP Spoofing (Classic MITM)",
                  type: "detail",
                  explanation: "Attacker poisons victim and gateway ARP caches to position self between them.",
                  children: [
                    {
                      name: "Level4: ARP Proxying & Forwarding Techniques",
                      type: "detail",
                      explanation: "Attacker sets up IP forwarding and optionally NAT to transparently proxy traffic.",
                      children: [
                        {
                          name: "Level5: Payload Manipulation & Session Hijack",
                          type: "detail",
                          explanation: "How attacker modifies responses or injects payloads to capture creds or persistent access.",
                        }
                      ]
                    }
                  ]
                },
                {
                  name: "Level3: ARP Cache Poisoning at Scale (Network-wide)",
                  type: "detail",
                  explanation: "Mass poisoning across VLAN/segment to intercept multiple hosts or segment-wide traffic.",
                  children: [
                    {
                      name: "Level4: Switch-level Countermeasures",
                      type: "detail",
                      explanation: "Configure port-security, CAM limits, storm-control and Dynamic ARP Inspection.",
                      children: [
                        {
                          name: "Level5: Operational Playbook for Mitigation",
                          type: "detail",
                          explanation: "Step-by-step ops to detect and contain mass ARP poisoning in production.",
                        }
                      ]
                    }
                  ]
                }
              ]
            },
            {
              name: "Level2: Detection, Monitoring & Forensics",
              type: "sub_topic",
              explanation: "How to detect ARP-MITM in real time, forensically analyze captures, and create alerts (SIEM).",
              details: "Both network-based and host-based detection techniques with sample queries and detection signatures.",
              children: [
                {
                  name: "Level3: Network Detection Rules",
                  type: "detail",
                  explanation: "Signatures and heuristics: duplicate IP mapped to multiple MACs, high frequency ARP replies, gratuitous ARP spikes.",
                  children: [
                    {
                      name: "Level4: Example Detection Signatures",
                      type: "detail",
                      explanation: "Practical IDS rules and SIEM queries (Hinglish explanation + examples).",
                      children: [
                        {
                          name: "Level5: Forensic Workflow & Evidence Collection",
                          type: "detail",
                          explanation: "Collect PCAPs, switch CAM snapshots, host ARP caches, DHCP server logs; preserve chain-of-custody.",
                        }
                      ]
                    }
                  ]
                },
                {
                  name: "Level3: Host-based Detection",
                  type: "detail",
                  explanation: "Endpoint sensors can detect ARP cache changes, unexpected gateway MAC changes, or new default gateway.",
                  children: [
                    {
                      name: "Level4: Example Host Monitors & Scripts",
                      type: "detail",
                      explanation: "Lightweight scripts to run as service to detect gateway MAC change and notify.",
                      children: [
                        {
                          name: "Level5: Playbook for SOC Triage on Host Alert",
                          type: "detail",
                          explanation: "SOC steps after host-based ARP alert: isolate host, capture memory/pcap, query switch, check for lateral movement.",
                        }
                      ]
                    }
                  ]
                }
              ]
            },
            {
              name: "Level2: Defenses, Hardening & Mitigation",
              type: "sub_topic",
              explanation: "Network and host-level mitigations from basic to advanced (DAI, 802.1X, static mapping, encryption).",
              details: "Prevention, detection, containment and recovery strategies in layered defenses.",
              children: [
                {
                  name: "Level3: Network Layer Protections",
                  type: "detail",
                  explanation: "Switch features: DHCP Snooping, Dynamic ARP Inspection (DAI), Port Security, 802.1X NAC.",
                  children: [
                    {
                      name: "Level4: Example Config Snippets",
                      type: "detail",
                      explanation: "Concrete config examples (Hinglish comments) for Cisco-like switches.",
                      children: [
                        {
                          name: "Level5: Validation & Testing Procedures",
                          type: "detail",
                          explanation: "How to test that protections work without causing outages (lab first).",
                        }
                      ]
                    }
                  ]
                },
                {
                  name: "Level3: Application & Transport Layer Mitigations",
                  type: "detail",
                  explanation: "Even if ARP MITM occurs, TLS and secure auth reduce impact.",
                  children: [
                    {
                      name: "Level4: TLS Best Practices",
                      type: "detail",
                      explanation: "Prevent SSL stripping and payload manipulation even under MITM conditions.",
                      children: [
                        {
                          name: "Level5: Incident Response for Suspected MITM",
                          type: "detail",
                          explanation: "Containment steps when MITM suspected despite TLS: rotate keys, reprovision certs, forensic capture.",
                        }
                      ]
                    }
                  ]
                }
              ]
            },
            {
              name: "Level2: OSINT, Red Teaming & Responsible Use",
              type: "sub_topic",
              explanation: "How ARP techniques are used in red-team/OSINT labs (ethical), and how defenders can use OSINT to map network risks.",
              details: "Always legal and authorized testing only. Use findings to remediate, not exploit.",
              children: [
                {
                  name: "Level3: Reconnaissance & Mapping",
                  type: "detail",
                  explanation: "Local OSINT: map active hosts, gateways, services using ARP/gratuitous ARP and passive sniffing.",
                  children: [
                    {
                      name: "Level4: Red Team Planning",
                      type: "detail",
                      explanation: "Plan MITM with minimal footprint: timing, selective targets, exfil channels, opsec.",
                      children: [
                        {
                          name: "Level5: Ethical Reporting Template",
                          type: "detail",
                          explanation: "How to report findings to stakeholders responsibly (Hinglish template).",
                        }
                      ]
                    }
                  ]
                },
                {
                  name: "Level3: Threat Intelligence & IOC Sharing",
                  type: "detail",
                  explanation: "Share relevant indicators of compromise (MACs, attacker IPs, tooling fingerprints) with SOC and peers.",
                  children: [
                    {
                      name: "Level4: Building Detection Signatures from Red Team PoC",
                      type: "detail",
                      explanation: "Convert PoC behaviors into SIEM rules and IDS signatures.",
                      children: [
                        {
                          name: "Level5: Continuous Improvement Cycle",
                          type: "detail",
                          explanation: "Test -> detect -> tune -> deploy: keep detection updated as attacker TTPs evolve.",
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          ]
        },
        // --- END OF INTEGRATED DEEP_DATA_TOPIC ---

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


// ---------------------------------------------------------------------------------------------------
// 2. D3.js LOGIC AND UTILITIES (Original logic maintained, DATA replaced)
// ---------------------------------------------------------------------------------------------------

let i = 0, duration = 750, root;
const margin = { top: 20, right: 100, bottom: 20, left: 100 };
const width = 1200 - margin.right - margin.left;
const height = 800 - margin.top - margin.bottom;

// Check for the D3 library and the necessary SVG element
if (typeof d3 === 'undefined' || !document.getElementById("treeSvg")) {
    console.error("D3.js library not loaded or '#treeSvg' element not found. The visualization will not run.");
    // Exit if dependencies are missing
    // return; 
}


const svgElement = d3.select("#treeSvg");
const svg = svgElement
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

svgElement.call(zoom);

// Convert the flat data to a hierarchical structure
root = d3.hierarchy(DATA_DEEP_DIVE, d => d.children);
root.x0 = height / 2;
root.y0 = 0;

// Store all nodes in a flat list for searching
const flatList = [];

// *** FIX: Collapse all nodes initially (including the first level) ***
root.each(d => {
  flatList.push(d.data);
  // Initially collapse all children below the top level
  if (d.children) {
    d._children = d.children; // Store children in _children
    d.children = null;       // Collapse them
  }
});

// Utility function to show details in the right panel
const panelTitle = document.getElementById('panelTitle');
const panelShort = document.getElementById('panelShort');
const panelInstall = document.getElementById('panelInstall');
const panelUsage = document.getElementById('panelUsage');
const panelUse = document.getElementById('panelUse');
const explainList = document.getElementById('explainList');

function showDetails(d) {
  if (panelTitle) panelTitle.textContent = d.name;
  if (panelShort) panelShort.textContent = d.short || d.details || d.explanation || "No short summary available.";
  if (panelInstall) panelInstall.textContent = d.install || "n/a (Not a command/tool)";
  if (panelUsage) panelUsage.textContent = d.usage || "Select a leaf node for usage example.";
  if (panelUse) panelUse.textContent = d.details || d.explanation || "No deep explanation available. Explore further branches.";

  // Highlight the corresponding item in the explanations list
  if (explainList) {
    const activeItems = explainList.querySelectorAll('.item');
    activeItems.forEach(item => item.classList.remove('active'));
    const activeItem = explainList.querySelector(`.item[data-name="${d.name}"]`);
    if (activeItem) {
      activeItem.classList.add('active');
      activeItem.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }

  // Highlight the node on the tree
  d3.selectAll(".node").classed("highlight", false).classed("dimmed", false);
  d3.selectAll(".link").classed("highlight", false);

  let current = d;
  while(current) {
    // Only highlight if the node ID is set (i.e., it has been rendered)
    if (current.id) {
        d3.select(`#node-${current.id}`).classed("highlight", true);
        if (current.parent) {
             d3.select(`#link-${current.id}`).classed("highlight", true); // Links are mapped by child's ID in the original code
        }
    }
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
  svgElement.transition()
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
if (searchInput) {
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
          if (current.id) { // Ensure ID exists before selection
             d3.select(`#node-${current.id}`).classed("dimmed", false).classed("highlight", true);
          }
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
}

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

if (document.getElementById('expandAll')) {
    document.getElementById('expandAll').addEventListener('click', () => {
      root.each(d => {
        d.children = d._children || d.children;
        d._children = null;
      });
      update(root);
      centerNode(root);
    });
}

if (document.getElementById('collapseAll')) {
    document.getElementById('collapseAll').addEventListener('click', () => {
      root.each(d => {
        if (d.depth > 0 && d.children) {
          d._children = d.children;
          d.children = null;
        }
      });
      // Keep the first level expanded (Original logic, retained for button function)
      if (root.children) {
        root.children.forEach(c => { c.children = c._children || c.children; c._children = null; });
      }
      update(root);
      centerNode(root);
    });
}

// Theme Toggle
if (document.getElementById('toggleTheme')) {
    document.getElementById('toggleTheme').addEventListener('click', () => {
      document.body.classList.toggle('theme-dark');
      document.body.classList.toggle('theme-light');
    });
}

// Export JSON (for the user's convenience)
if (document.getElementById('exportJson')) {
    document.getElementById('exportJson').addEventListener('click', () => {
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(DATA_DEEP_DIVE, null, 2));
      const downloadAnchorNode = document.createElement('a');
      downloadAnchorNode.setAttribute("href", dataStr);
      downloadAnchorNode.setAttribute("download", "networking_data_deep_dive.json");
      document.body.appendChild(downloadAnchorNode);
      downloadAnchorNode.click();
      downloadAnchorNode.remove();
    });
}


// ---------------------------------------------------------------------------------------------------
// 4. LEARN PATH AND EXPLANATION LIST
// ---------------------------------------------------------------------------------------------------

// Mock Learn Paths based on the deep structure
const beginner = ["OSI Reference Model (7 Layers)", "IP Addressing & Subnetting", "Ping (Packet Inter-Network Groper)"];
const intermediate = ["Routing Protocols", "NAT (Port Address Translation)", "ARP Protocol and MITM Attacks"]; // Updated to include new topic
const advanced = ["BGP (Border Gateway Protocol)", "EIGRP (Enhanced Interior Gateway Routing Protocol)", "Level2: Defenses, Hardening & Mitigation"]; // Updated to include new topic

function populatePath(id, path) {
  const ol = document.getElementById(id);
  if (!ol) return;
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
  if (!explainList) return;

  const allNodes = [];
  function traverse(node) {
    if (node.children) {
      node.children.forEach(traverse);
    }
    // Include nodes with explanation, details, or short for the list
    if (node.explanation || node.details || node.short) { 
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
    // Prioritize explanation/details for the list, falling back to short
    div.innerHTML = `<strong>${d.name}</strong>: ${d.explanation || d.details || d.short || '...click for details'}`; 
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

// Execute path and list population
populatePath("pathBeginner", beginner);
populatePath("pathIntermediate", intermediate);
populatePath("pathAdvanced", advanced);
populateExplanationList(DATA_DEEP_DIVE);


// ---------------------------------------------------------------------------------------------------
// 5. INITIALIZATION
// ---------------------------------------------------------------------------------------------------

// *** FIX: Start fully collapsed by only calling update on the root ***
update(root);

// accessibility: keyboard search enter focuses first match
if (searchInput) {
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
}

// center root on load and apply initial zoom
setTimeout(() => {
  // zoom to show central area
  if (svgElement) {
    svgElement.call(zoom.transform, d3.zoomIdentity.translate(80, 20).scale(1));
  }
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
