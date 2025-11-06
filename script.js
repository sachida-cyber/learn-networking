// Networking Mastery Tree Map - V3 Deep Explanations (Enhanced & Collapsed)
// All content in Hinglish (simple Hindi-English mix)

// ---------------------------------------------------------------------------------------------------
// 1. DATA STRUCTURE (Multi-Level, Super Informative)
// ---------------------------------------------------------------------------------------------------

const DATA_DEEP_DIVE = {
  "name": "Networking Mastery Tree Map - Deep Dive V3",
  "children": [
    {
      "name": "Networking Fundamentals & Models",
      "type": "category",
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
                {"name": "Layer 7 Protocols", "type": "protocol", "usage": "Email, Web browsing, File transfer jaise services chalti hain.", "install": "HTTP, DNS, SMTP"},
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
      "type": "category",
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
      "type": "category",
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
{
  "name": "Network Access & Media",
  "type": "category",
  "children": [
    {
      "name": "Network Media & Physical Layer",
      "type": "topic",
      "children": [
        {"name": "UTP & Fiber Optic Cabling", "type": "detail"},
        {"name": "PoE (Power over Ethernet)", "type": "detail"}
      ]
    },
    {
      "name": "Advanced Switching (L2)",
      "type": "topic",
      "children": [
        {"name": "VLANs & Trunking (802.1Q)", "type": "protocol"},
        {"name": "Spanning Tree Protocol (STP)", "type": "protocol"},
        {"name": "MAC Address Table", "type": "detail"}
      ]
    },
    {
      "name": "ARP & DHCP",
      "type": "topic",
      "children": [
        {"name": "ARP Process (L2 to L3 Mapping)", "type": "protocol"},
        {"name": "DHCP DORA Process", "type": "protocol"}
      ]
    }
  ]
}


// ---------------------------------------------------------------------------------------------------
// 2. D3.js LOGIC AND UTILITIES (Enhanced for color and depth)
// ---------------------------------------------------------------------------------------------------

let i = 0, duration = 750, root;
const margin = { top: 20, right: 100, bottom: 20, left: 100 };
const width = 1200 - margin.right - margin.left;
const height = 800 - margin.top - margin.bottom;

// Define color scale for different node types
function getColor(d) {
    switch (d.data.type) {
        case 'category': return '#a8dadc'; // Light Blue/Teal for Top Level
        case 'topic': return '#457b9d';    // Medium Blue for Main Topics
        case 'sub_topic': return '#1d3557'; // Dark Blue for Sub-Topics
        case 'protocol': return '#e63946';  // Red for Protocols
        case 'tool': return '#ffba08';      // Yellow/Orange for Tools
        case 'detail': return '#f1faee';    // Off-White for specific details
        default: return '#f1faee';
    }
}


// Check for the D3 library and the necessary SVG element
if (typeof d3 === 'undefined' || !document.getElementById("treeSvg")) {
    console.error("D3.js library not loaded or '#treeSvg' element not found. The visualization will not run.");
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

// *** FIX: Collapse all children initially to start at a single root node ***
root.each(d => {
  flatList.push(d.data);
  if (d.children) {
    d._children = d.children; // Store children in _children
    d.children = null;       // Collapse them
  }
});

// Utility functions (showDetails, click, centerNode, toggleAll) remain the same as the previous version
// ... (omitted for brevity, assume they are pasted here) ...

// Utility function to show details in the right panel
const panelTitle = document.getElementById('panelTitle');
const panelShort = document.getElementById('panelShort');
const panelInstall = document.getElementById('panelInstall');
const panelUsage = document.getElementById('panelUsage');
const panelUse = document.getElementById('panelUse');
const explainList = document.getElementById('explainList');

function showDetails(d) {
  if (panelTitle) panelTitle.textContent = d.name;
  if (panelShort) panelShort.textContent = d.short || d.details || "No short summary available.";
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
    .on('click', click);

  // Add Circle for the nodes
  nodeEnter.append('circle')
    .attr('r', 1e-6)
    .style("fill", d => d._children ? getColor(d) : "#000") // Use custom color for collapsed
    .style("stroke", d => getColor(d));                      // Use custom color for stroke

  // Add text for the nodes
  nodeEnter.append('text')
    .attr("dy", ".35em")
    .attr("x", d => d.children || d._children ? -13 : 13)
    .attr("text-anchor", d => d.children || d._children ? "end" : "start")
    .text(d => d.data.name)
    .style('fill', '#f1faee')
    .style('font-weight', '500')
    .style('opacity', 1.0);

  // Update the transition for nodes
  const nodeUpdate = nodeEnter.merge(node);

  // Transition to the new position
  nodeUpdate.transition()
    .duration(duration)
    .attr("transform", d => "translate(" + d.y + "," + d.x + ")");

  // Update the node attributes and style
  nodeUpdate.select('circle')
    .attr('r', 8)
    // *** ENHANCEMENT: Use type-based color and adjust fill for better depth ***
    .style("fill", d => d._children ? getColor(d) : "#000") 
    .style("stroke", d => getColor(d))
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
    // *** ENHANCEMENT: Opacity based on depth for visual hierarchy ***
    .style("stroke-opacity", d => 1 / (d.depth + 1))
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
// 3. UI AND EVENT HANDLERS (No significant change, ensuring element checks)
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
      // *** FIX: Collapse all nodes except the root ***
      root.each(d => {
        if (d.depth >= 1 && d.children) { // Only collapse nodes deeper than the root
          d._children = d.children;
          d.children = null;
        }
      });
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

// Export JSON
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
// 4. LEARN PATH AND EXPLANATION LIST (No change)
// ---------------------------------------------------------------------------------------------------

// Mock Learn Paths based on the deep structure
const beginner = ["OSI Reference Model (7 Layers)", "IP Addressing & Subnetting", "Ping (Packet Inter-Network Groper)"];
const intermediate = ["Routing Protocols", "NAT (Port Address Translation)", "Stateful Inspection Advantages"];
const advanced = ["BGP (Border Gateway Protocol)", "EIGRP (Enhanced Interior Gateway Routing Protocol)", "IPsec (Internet Protocol Security)"];

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
    // Only include nodes with a summary/details for the list
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
    // Zoom/Pan slightly to the right to better position the root node
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
/* *** NEW STYLE FOR LINK DEPTH *** */
.link {
    fill: none;
    stroke: #457b9d; /* Base link color (Matches a primary topic color) */
    stroke-width: 1.5px;
}
.link.highlight {
    stroke: #e63946; /* Highlight color (Matches Protocol/Important node) */
    stroke-width: 2.5px;
}
`;
document.head.appendChild(style);
