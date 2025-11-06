// Networking Mastery Tree Map
// All content in Hinglish (simple Hindi-English mix)
// DATA: 20 categories × 10 entries = 200 leaf nodes
const DATA = {
  "name": "Networking Mastery",
  "children": [
    {
      "name":"Networking Basics",
      "children":[
        {"name":"OSI Model","type":"topic","short":"OSI ke 7 layer: physical se application tak.","install":"n/a","usage":"OSI model se network design samjho"},
        {"name":"TCP/IP Stack","type":"topic","short":"TCP/IP 4 layers — internet stack model.","install":"n/a","usage":"IP/TCP ka behavior samajhne ke liye"},
        {"name":"Ports","type":"topic","short":"Ports se services identify karte hain (80,443...).","install":"n/a","usage":"port 80 HTTP ke liye hota hai"},
        {"name":"IP Address","type":"topic","short":"IPv4/IPv6 address host identify karte hain.","install":"n/a","usage":"ip address 192.168.1.10 jaise"},
        {"name":"MAC Address","type":"topic","short":"Hardware address jo NIC ko unique banata.","install":"n/a","usage":"arp -a se MAC dekho"},
        {"name":"ARP","type":"protocol","short":"IP se MAC map karne ka protocol.","install":"n/a","usage":"arp -a, arp -s"},
        {"name":"Subnetting","type":"topic","short":"Network ko subnets mein divide karna.","install":"n/a","usage":"CIDR /24 etc se subnet calc"},
        {"name":"Broadcast vs Multicast","type":"topic","short":"Broadcast sabko send, multicast group ko.","install":"n/a","usage":"mDNS, IGMP jaise protocols"},
        {"name":"Frames vs Packets","type":"topic","short":"Layer wise data units: frame, packet, segment.","install":"n/a","usage":"OSI layer mapping samjho"},
        {"name":"Collision vs Congestion","type":"topic","short":"Collision MAC level, congestion link/network level.","install":"n/a","usage":"switching se collisions kam hote hain"}
      ]
    },
    {
      "name":"Network Configuration",
      "children":[
        {"name":"ifconfig","type":"command","short":"Old Linux tool interface dekhne ke liye.","install":"sudo apt install net-tools","usage":"ifconfig -a"},
        {"name":"ip (iproute2)","type":"command","short":"Modern tool for ip addresses/routes.","install":"sudo apt install iproute2","usage":"ip addr show; ip route"},
        {"name":"route","type":"command","short":"Routing table dekhne/modify karne ke liye.","install":"sudo apt install net-tools","usage":"route -n"},
        {"name":"netplan","type":"tool","short":"Ubuntu system network config ka YAML tool.","install":"preinstalled on new Ubuntu","usage":"sudo netplan apply"},
        {"name":"nmcli","type":"command","short":"NetworkManager CLI for wifi/eth management.","install":"sudo apt install network-manager","usage":"nmcli device status"},
        {"name":"systemd-networkd","type":"service","short":"systemd ka network stack service.","install":"sudo apt install systemd-networkd","usage":"sudo systemctl status systemd-networkd"},
        {"name":"resolv.conf","type":"file","short":"DNS resolver configuration file in Linux.","install":"n/a","usage":"cat /etc/resolv.conf"},
        {"name":"hostnamectl","type":"command","short":"Set/view system hostname and related info.","install":"n/a","usage":"hostnamectl set-hostname myhost"},
        {"name":"ethtool","type":"tool","short":"NIC settings jaise speed/duplex change karne ko.","install":"sudo apt install ethtool","usage":"ethtool eth0"},
        {"name":"systemctl network","type":"topic","short":"Network services ko manage karne ke liye systemctl use hota.","install":"n/a","usage":"sudo systemctl restart networking"}
      ]
    },
    {
      "name":"Diagnostics Tools",
      "children":[
        {"name":"ping","type":"command","short":"Host reachable hai ya nahi check karta hai.","install":"sudo apt install iputils-ping","usage":"ping google.com"},
        {"name":"traceroute","type":"command","short":"Packet kin-kin routers se guzra woh batata.","install":"sudo apt install traceroute","usage":"traceroute google.com"},
        {"name":"mtr","type":"tool","short":"Combines ping + traceroute live view.","install":"sudo apt install mtr","usage":"mtr google.com"},
        {"name":"nslookup","type":"tool","short":"DNS lookup simple CLI tool.","install":"sudo apt install dnsutils","usage":"nslookup example.com"},
        {"name":"dig","type":"tool","short":"Powerful DNS query tool.","install":"sudo apt install dnsutils","usage":"dig +short example.com"},
        {"name":"arping","type":"command","short":"ARP level ping for LAN hosts.","install":"sudo apt install iputils-arping","usage":"arping -I eth0 192.168.1.1"},
        {"name":"netstat","type":"command","short":"Old tool for sockets and connections.","install":"sudo apt install net-tools","usage":"netstat -tulpn"},
        {"name":"ss","type":"command","short":"Modern socket statistics tool.","install":"n/a (iproute2)","usage":"ss -tuln"},
        {"name":"tcpdump","type":"tool","short":"Packet capture in CLI.","install":"sudo apt install tcpdump","usage":"sudo tcpdump -i eth0"},
        {"name":"wireshark","type":"tool","short":"GUI packet analyzer for deep inspection.","install":"sudo apt install wireshark","usage":"wireshark &"}
      ]
    },
    {
      "name":"Protocols",
      "children":[
        {"name":"HTTP","type":"protocol","short":"Web ka basic protocol — request/response.","install":"n/a","usage":"curl -I http://example.com"},
        {"name":"HTTPS","type":"protocol","short":"HTTP over TLS — secure web traffic.","install":"n/a","usage":"https://example.com"},
        {"name":"FTP","type":"protocol","short":"File transfer protocol (legacy).","install":"sudo apt install ftp","usage":"ftp ftp.example.com"},
        {"name":"SSH","type":"protocol","short":"Secure shell for remote login.","install":"sudo apt install openssh-client","usage":"ssh user@host"},
        {"name":"SMTP","type":"protocol","short":"Email sending protocol.","install":"n/a","usage":"telnet smtp.example.com 25"},
        {"name":"SNMP","type":"protocol","short":"Monitoring protocol for devices.","install":"sudo apt install snmp","usage":"snmpwalk -v2c"},
        {"name":"DNS","type":"protocol","short":"Name to IP resolution system.","install":"n/a","usage":"dig example.com"},
        {"name":"DHCP","type":"protocol","short":"Dynamic IP assignment protocol.","install":"n/a","usage":"dhclient eth0"},
        {"name":"TLS","type":"protocol","short":"Transport Layer Security for encryption.","install":"n/a","usage":"openssl s_client -connect example.com:443"},
        {"name":"ICMP","type":"protocol","short":"Ping etc use ICMP for network diagnostics.","install":"n/a","usage":"ping uses ICMP echo"}
      ]
    },
    {
      "name":"Network Devices",
      "children":[
        {"name":"Router","type":"device","short":"Packets ko different networks ke beech forward karta.","install":"n/a","usage":"Configure routing tables"},
        {"name":"Switch","type":"device","short":"LAN devices connect karne aur frames forward karne ke liye.","install":"n/a","usage":"VLAN configure karna"},
        {"name":"Hub","type":"device","short":"Legacy device — broadcast karta sabko.","install":"n/a","usage":"Mostly obsolete"},
        {"name":"Bridge","type":"device","short":"Two LAN segments ko layer2 pe join karta.","install":"n/a","usage":"brctl addbr br0"},
        {"name":"Firewall","type":"device","short":"Traffic allow/deny karne ka device/software.","install":"n/a","usage":"iptables/ufw rules banaye jaate"},
        {"name":"Load Balancer","type":"device","short":"Traffic distribute karta multiple servers pe.","install":"n/a","usage":"HAProxy/Nginx load balancing"},
        {"name":"Access Point","type":"device","short":"Wireless devices ko connect karwata.","install":"n/a","usage":"AP mode setup for Wi-Fi"},
        {"name":"Modem","type":"device","short":"ISP se physical connection handle karta.","install":"n/a","usage":"Cable/DSL modem setup"},
        {"name":"Gateway","type":"device","short":"Network boundary par routing + services provide karta.","install":"n/a","usage":"Default gateway configure karo"},
        {"name":"Repeater","type":"device","short":"Signal boost karke range badhata.","install":"n/a","usage":"Wi-Fi range extender"}
      ]
    },
    {
      "name":"Security",
      "children":[
        {"name":"Firewall Concepts","type":"topic","short":"Packet filtering, stateful, application firewalls.","install":"n/a","usage":"Define allow/deny rules"},
        {"name":"VPNs","type":"topic","short":"Encrypted tunnel remote networks connect karne ko.","install":"n/a","usage":"OpenVPN/WireGuard use karte"},
        {"name":"IDS/IPS","type":"topic","short":"Intrusion detection/prevention systems.","install":"n/a","usage":"Snort/Suricata deploy karte"},
        {"name":"SSL/TLS","type":"topic","short":"Secure encryption for web and protocols.","install":"n/a","usage":"Certs manage with Let's Encrypt"},
        {"name":"Encryption Tools","type":"topic","short":"OpenSSL, GPG for data encryption.","install":"sudo apt install openssl gnupg","usage":"openssl genrsa"},
        {"name":"Port Knocking","type":"technique","short":"Stealth open ports using knock sequences.","install":"n/a","usage":"iptables + knockd"},
        {"name":"Zero Trust","type":"concept","short":"Trust ko assume na karke verify karna.","install":"n/a","usage":"Microsegmentation and strong auth"},
        {"name":"WAF","type":"tool","short":"Web Application Firewall protect web apps.","install":"ModSecurity etc","usage":"mod_security rules"},
        {"name":"SSH Hardening","type":"topic","short":"Key auth, disable root, port change.","install":"n/a","usage":"Use ssh-keygen; disable password auth"},
        {"name":"fail2ban","type":"tool","short":"Brute-force attempts block karne ka tool.","install":"sudo apt install fail2ban","usage":"sudo systemctl enable fail2ban"}
      ]
    },
    {
      "name":"Monitoring Tools",
      "children":[
        {"name":"Wireshark","type":"tool","short":"Packet-level capture and analysis GUI.","install":"sudo apt install wireshark","usage":"Capture filters use karo"},
        {"name":"tcpdump","type":"tool","short":"CLI packet capture for quick checks.","install":"sudo apt install tcpdump","usage":"sudo tcpdump -i eth0 port 80"},
        {"name":"nmap","type":"tool","short":"Network scanning and port discovery.","install":"sudo apt install nmap","usage":"nmap -sS 192.168.1.0/24"},
        {"name":"netstat/ss","type":"tool","short":"Active connections and listening ports check karne ke liye.","install":"n/a","usage":"ss -tuln"},
        {"name":"Prometheus","type":"tool","short":"Time-series monitoring and metrics store.","install":"download binaries","usage":"scrape /metrics endpoints"},
        {"name":"Grafana","type":"tool","short":"Visualization dashboard for metrics.","install":"download grafana","usage":"Connect Prometheus datasource"},
        {"name":"Zabbix","type":"tool","short":"Full-stack monitoring solution.","install":"install zabbix-server","usage":"Agent-based monitoring"},
        {"name":"Nagios","type":"tool","short":"Classic monitoring and alerting system.","install":"sudo apt install nagios","usage":"Define services and checks"},
        {"name":"vnStat","type":"tool","short":"Traffic monitoring per interface.","install":"sudo apt install vnstat","usage":"vnstat -i eth0"},
        {"name":"bmon","type":"tool","short":"Bandwidth monitor simple TUI.","install":"sudo apt install bmon","usage":"bmon -p eth0"}
      ]
    },
    {
      "name":"Wireless & IoT",
      "children":[
        {"name":"Wi-Fi Basics","type":"topic","short":"2.4/5GHz, channels, SSID, BSSID samjho.","install":"n/a","usage":"Choose proper channel"},
        {"name":"Access Points","type":"device","short":"Wi-Fi access provide karte.","install":"n/a","usage":"AP config: SSID, security"},
        {"name":"WPA/WPA2/WPA3","type":"topic","short":"Wi-Fi security standards.","install":"n/a","usage":"Use WPA3 where possible"},
        {"name":"802.11 Standards","type":"topic","short":"a/b/g/n/ac/ax versions aur unki speeds.","install":"n/a","usage":"Choose equipment accordingly"},
        {"name":"IoT Protocols","type":"topic","short":"MQTT, CoAP, LoRaWAN jaise lightweight protocols.","install":"n/a","usage":"Use MQTT for telemetry"},
        {"name":"Site Survey","type":"practice","short":"AP placement aur interference analyze karna.","install":"use inSSIDer or Wi-Fi analyzers","usage":"Plan channels and AP density"},
        {"name":"Rogue AP Detection","type":"topic","short":"Unauthorized APs find karna security ke liye.","install":"n/a","usage":"Use monitoring + WIPS"},
        {"name":"Mesh Wi-Fi","type":"topic","short":"Multiple APs mesh karke coverage badhana.","install":"n/a","usage":"Mesh nodes add karo"},
        {"name":"WPS Risks","type":"topic","short":"WPS vulnerable hota, disable karna better.","install":"n/a","usage":"Turn off WPS"},
        {"name":"Bluetooth Networking","type":"topic","short":"PAN and BLE used for IoT device communication.","install":"n/a","usage":"BLE beacons for location"}
      ]
    },
    {
      "name":"Servers & Services",
      "children":[
        {"name":"Apache","type":"server","short":"Popular web server, modules aur vhosts use hota.","install":"sudo apt install apache2","usage":"sudo systemctl start apache2"},
        {"name":"Nginx","type":"server","short":"Lightweight reverse proxy and web server.","install":"sudo apt install nginx","usage":"nginx -t; sudo systemctl restart nginx"},
        {"name":"Bind9","type":"service","short":"DNS server for authoritative/resolving zones.","install":"sudo apt install bind9","usage":"named.conf configure karo"},
        {"name":"dhcpd","type":"service","short":"ISC DHCP server dynamic IP assign karta.","install":"sudo apt install isc-dhcp-server","usage":"/etc/dhcp/dhcpd.conf edit"},
        {"name":"OpenVPN","type":"service","short":"VPN server for secure remote access.","install":"sudo apt install openvpn","usage":"openvpn --config server.conf"},
        {"name":"Samba","type":"service","short":"Windows-style file sharing from Linux.","install":"sudo apt install samba","usage":"smb.conf configure karo"},
        {"name":"FTP Server","type":"service","short":"vsftpd ya proftpd for FTP services.","install":"sudo apt install vsftpd","usage":"configure /etc/vsftpd.conf"},
        {"name":"DNS Resolver","type":"service","short":"Local resolver jaise systemd-resolved ya unbound.","install":"sudo apt install unbound","usage":"unbound-control stats"},
        {"name":"DHCP Relay","type":"service","short":"DHCP requests forward between networks.","install":"isc-dhcp-relay","usage":"relay configuration"},
        {"name":"Reverse Proxy","type":"concept","short":"Requests backend servers ko forward karta.","install":"use nginx/haproxy","usage":"proxy_pass in nginx"}
      ]
    },
    {
      "name":"Cloud Networking",
      "children":[
        {"name":"AWS VPC","type":"topic","short":"Virtual network in AWS for isolation.","install":"n/a","usage":"Create subnets and route tables"},
        {"name":"Subnets","type":"topic","short":"Subdivide VPC into smaller networks.","install":"n/a","usage":"public/private subnet design"},
        {"name":"Security Groups","type":"topic","short":"Instance-level firewall in AWS.","install":"n/a","usage":"Allow ports 22/80 as needed"},
        {"name":"NAT Gateway","type":"topic","short":"Outbound internet access for private subnets.","install":"n/a","usage":"Use NAT for private instances"},
        {"name":"Route Tables","type":"topic","short":"Network routes define how traffic flows.","install":"n/a","usage":"Associate route table with subnet"},
        {"name":"Azure VNets","type":"topic","short":"Azure ka virtual network concept.","install":"n/a","usage":"Create subnets and NSGs"},
        {"name":"Load Balancer (Cloud)","type":"topic","short":"Distribute traffic across cloud instances.","install":"n/a","usage":"ALB/NLB usage patterns"},
        {"name":"Transit Gateway","type":"topic","short":"Connect multiple VPCs centrally.","install":"n/a","usage":"Use for hub-and-spoke architecture"},
        {"name":"Cloud Peering","type":"topic","short":"Network peering between VPCs for private comms.","install":"n/a","usage":"VPC peering setup"},
        {"name":"VPN Gateway","type":"topic","short":"Site-to-cloud VPN connections.","install":"n/a","usage":"IPSec tunnels config"}
      ]
    },
    {
      "name":"Linux Networking Commands",
      "children":[
        {"name":"iptables","type":"command","short":"Classic Linux packet filter and NAT tool.","install":"n/a","usage":"sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT"},
        {"name":"nftables","type":"command","short":"Modern replacement for iptables.","install":"sudo apt install nftables","usage":"nft list ruleset"},
        {"name":"ufw","type":"tool","short":"Simple firewall frontend for iptables.","install":"sudo apt install ufw","usage":"sudo ufw allow 22"},
        {"name":"firewalld","type":"tool","short":"Dynamic firewall manager for Linux.","install":"sudo apt install firewalld","usage":"sudo firewall-cmd --list-all"},
        {"name":"tc","type":"command","short":"Traffic control for shaping and queuing.","install":"iproute2 package","usage":"tc qdisc add dev eth0 root tbf ..."},
        {"name":"hostname","type":"command","short":"Show or set system hostname.","install":"n/a","usage":"hostnamectl set-hostname myhost"},
        {"name":"route (Linux)","type":"command","short":"Routing table view and change.","install":"n/a","usage":"route -n"},
        {"name":"arp","type":"command","short":"ARP table view and manipulation.","install":"n/a","usage":"arp -n"},
        {"name":"ss","type":"command","short":"Socket statistics — modern netstat.","install":"n/a","usage":"ss -s"},
        {"name":"ipset","type":"tool","short":"Manage sets of IPs for firewalling.","install":"sudo apt install ipset","usage":"ipset create ban hash:ip"}
      ]
    },
    {
      "name":"Troubleshooting",
      "children":[
        {"name":"Latency Check","type":"topic","short":"Round-trip time measure karna (ping).","install":"n/a","usage":"ping -c 5 host"},
        {"name":"Packet Loss","type":"topic","short":"Packets drop ho rahe hain ya nahi check karna.","install":"n/a","usage":"mtr or ping statistics"},
        {"name":"Bandwidth Testing","type":"topic","short":"Throughput measure iperf se karte hain.","install":"sudo apt install iperf3","usage":"iperf3 -c server"},
        {"name":"Interface Errors","type":"topic","short":"RX/TX errors check karna ethtool ya ifconfig se.","install":"n/a","usage":"ifconfig eth0"},
        {"name":"DNS Troubles","type":"topic","short":"Name resolution fail hone par dig/nslookup use karo.","install":"sudo apt install dnsutils","usage":"dig @8.8.8.8 example.com"},
        {"name":"MTU Issues","type":"topic","short":"Fragmentation/MTU mismatch troubleshoot karo.","install":"n/a","usage":"ping -M do -s 1472 host"},
        {"name":"Asymmetric Routing","type":"topic","short":"Return path different ho to issues aate.","install":"n/a","usage":"Trace both directions"},
        {"name":"ARP Problems","type":"topic","short":"Duplicate MAC ya stale ARP entries check karo.","install":"n/a","usage":"arp -n"},
        {"name":"Route Flapping","type":"topic","short":"Frequent route changes cause instability.","install":"n/a","usage":"Check BGP/OSPF states"},
        {"name":"Service Reachability","type":"topic","short":"Port and firewall checks se confirm karo.","install":"n/a","usage":"telnet host port / nc host port"}
      ]
    },
    {
      "name":"Performance Tools",
      "children":[
        {"name":"iperf","type":"tool","short":"Throughput testing between two endpoints.","install":"sudo apt install iperf3","usage":"iperf3 -s (server) ; iperf3 -c server"},
        {"name":"bmon","type":"tool","short":"Bandwidth monitor in TUI.","install":"sudo apt install bmon","usage":"bmon -p eth0"},
        {"name":"ethtool","type":"tool","short":"NIC diagnostics and offload settings.","install":"sudo apt install ethtool","usage":"ethtool -S eth0"},
        {"name":"tc","type":"tool","short":"QoS and traffic shaping tool.","install":"iproute2 package","usage":"tc qdisc add ..."},
        {"name":"netperf","type":"tool","short":"Benchmark networking performance.","install":"sudo apt install netperf","usage":"netperf -H server"},
        {"name":"nload","type":"tool","short":"Realtime bandwidth monitor.","install":"sudo apt install nload","usage":"nload eth0"},
        {"name":"iftop","type":"tool","short":"Top-like interface bandwidth view.","install":"sudo apt install iftop","usage":"sudo iftop -i eth0"},
        {"name":"dstat","type":"tool","short":"Multiple system stats including network.","install":"sudo apt install dstat","usage":"dstat -n"},
        {"name":"vnstat","type":"tool","short":"Persistent network traffic logging.","install":"sudo apt install vnstat","usage":"vnstat -i eth0"},
        {"name":"sar","type":"tool","short":"System activity report with network stats.","install":"sudo apt install sysstat","usage":"sar -n DEV 1 3"}
      ]
    },
    {
      "name":"Network Automation",
      "children":[
        {"name":"Ansible","type":"tool","short":"Automate network config with playbooks.","install":"pip install ansible","usage":"ansible-playbook site.yml"},
        {"name":"Netmiko","type":"library","short":"Python library for SSH to network devices.","install":"pip install netmiko","usage":"from netmiko import ConnectHandler"},
        {"name":"Nornir","type":"tool","short":"Python automation framework for networks.","install":"pip install nornir","usage":"Write tasks and inventories"},
        {"name":"RESTCONF/NETCONF","type":"protocol","short":"API based network device config protocols.","install":"n/a","usage":"Use with YANG models"},
        {"name":"Python Scripts","type":"topic","short":"Custom scripts for device automation.","install":"n/a","usage":"Use paramiko/netmiko libraries"},
        {"name":"Jinja2 Templates","type":"tool","short":"Config templating for devices.","install":"pip install jinja2","usage":"Render device configs"},
        {"name":"GitOps","type":"concept","short":"Use git for managing network config changes.","install":"n/a","usage":"Store config in repo and deploy"},
        {"name":"API-Driven","type":"concept","short":"Device APIs for config and telemetry.","install":"n/a","usage":"Use REST APIs exposed by vendors"},
        {"name":"SSH Keys Automation","type":"practice","short":"Key-based auth for automated access.","install":"ssh-keygen","usage":"ssh-copy-id user@device"},
        {"name":"CI/CD for Network","type":"topic","short":"Testing and deploying network changes via pipelines.","install":"n/a","usage":"Use Jenkins/GitHub Actions"}
      ]
    },
    {
      "name":"Advanced Concepts",
      "children":[
        {"name":"VLAN","type":"concept","short":"Logical LAN partitioning on switches.","install":"n/a","usage":"switchport access/trunk commands"},
        {"name":"NAT","type":"concept","short":"Translate private to public IPs.","install":"n/a","usage":"iptables -t nat -A POSTROUTING ..."},
        {"name":"Proxy","type":"concept","short":"Intermediary for requests and caching.","install":"n/a","usage":"Squid / reverse proxy with nginx"},
        {"name":"Port Forwarding","type":"concept","short":"External port mapped to internal host.","install":"n/a","usage":"iptables or router NAT rules"},
        {"name":"ACLs","type":"concept","short":"Access lists to permit/deny traffic.","install":"n/a","usage":"Define rules on routers/firewalls"},
        {"name":"QoS","type":"concept","short":"Prioritize traffic types for performance.","install":"n/a","usage":"tc and DSCP markings"},
        {"name":"Proxy ARP","type":"concept","short":"Router answers ARP for another host.","install":"n/a","usage":"Used in some NAT setups"},
        {"name":"Hairpin NAT","type":"concept","short":"NAT loopback to access internal services via public IP.","install":"n/a","usage":"Enable on router for internal testing"},
        {"name":"TCP Windowing","type":"concept","short":"Flow control mechanism for TCP throughput.","install":"n/a","usage":"Tune TCP buffers"},
        {"name":"Bufferbloat","type":"topic","short":"Excessive buffering causing latency spikes.","install":"n/a","usage":"Use fq_codel to mitigate"}
      ]
    },
    {
      "name":"Routing & Switching",
      "children":[
        {"name":"Static Routing","type":"topic","short":"Manual fixed routes configure karte hain.","install":"n/a","usage":"ip route add 10.0.0.0/24 via 192.168.1.1"},
        {"name":"Dynamic Routing","type":"topic","short":"Protocols exchange routes automatically.","install":"n/a","usage":"Use OSPF/BGP"},
        {"name":"OSPF","type":"protocol","short":"Interior gateway protocol for dynamic routing.","install":"n/a","usage":"Area and LSAs configure karo"},
        {"name":"BGP","type":"protocol","short":"Inter-domain routing protocol for internet.","install":"n/a","usage":"AS numbers aur peering configure"},
        {"name":"EIGRP","type":"protocol","short":"Cisco proprietary routing protocol.","install":"n/a","usage":"Use on Cisco devices"},
        {"name":"RIP","type":"protocol","short":"Legacy distance-vector routing protocol.","install":"n/a","usage":"Mostly historical"},
        {"name":"STP","type":"protocol","short":"Spanning Tree to avoid loops on switches.","install":"n/a","usage":"Enable on switches"},
        {"name":"VRF","type":"concept","short":"Virtual routing instances for multi-tenancy.","install":"n/a","usage":"Separate routing tables per VRF"},
        {"name":"MPLS","type":"concept","short":"Label switched paths for traffic engineering.","install":"n/a","usage":"Use in service provider networks"},
        {"name":"EtherChannel","type":"technique","short":"Link aggregation to increase bandwidth.","install":"n/a","usage":"Configure LACP on switches"}
      ]
    },
    {
      "name":"DNS & Name Resolution",
      "children":[
        {"name":"Bind9","type":"service","short":"Popular DNS server for authoritative zones.","install":"sudo apt install bind9","usage":"zone files edit karein"},
        {"name":"resolv.conf","type":"file","short":"Local resolver configuration file.","install":"n/a","usage":"nameserver 8.8.8.8"},
        {"name":"dig","type":"tool","short":"Detailed DNS queries aur diagnostics.","install":"sudo apt install dnsutils","usage":"dig @8.8.8.8 example.com"},
        {"name":"nslookup","type":"tool","short":"Simple DNS lookup CLI.","install":"sudo apt install dnsutils","usage":"nslookup example.com"},
        {"name":"DNS Cache","type":"concept","short":"Local caching to speed name resolution.","install":"n/a","usage":"Use unbound or systemd-resolved"},
        {"name":"SRV Records","type":"record","short":"Service records for locating services like SIP.","install":"n/a","usage":"_sip._tcp.example.com"},
        {"name":"Reverse DNS","type":"concept","short":"IP se name map karna PTR records se.","install":"n/a","usage":"PTR record configure karo"},
        {"name":"Zone Transfer","type":"topic","short":"DNS data transfer between servers (AXFR).","install":"n/a","usage":"Allow secure transfers only"},
        {"name":"DNSSEC","type":"topic","short":"Sign DNS zones for authenticity.","install":"n/a","usage":"Enable DNSSEC on authoritative servers"},
        {"name":"Resolvers vs Authoritative","type":"topic","short":"Resolver query forward, authoritative answer zones.","install":"n/a","usage":"Design topology accordingly"}
      ]
    },
    {
      "name":"VPN & Tunneling",
      "children":[
        {"name":"OpenVPN","type":"tool","short":"Mature VPN solution using TLS.","install":"sudo apt install openvpn","usage":"openvpn --config client.ovpn"},
        {"name":"WireGuard","type":"tool","short":"Modern, lightweight VPN with keys.","install":"sudo apt install wireguard","usage":"wg-quick up wg0"},
        {"name":"IPSec","type":"protocol","short":"Standard for encrypted tunnels between networks.","install":"strongswan package","usage":"Configure IKE and ESP"},
        {"name":"GRE Tunnel","type":"technique","short":"Generic routing encapsulation for private links.","install":"n/a","usage":"ip tunnel add ..."},
        {"name":"SSH Tunneling","type":"technique","short":"Port forwarding via SSH for secure access.","install":"n/a","usage":"ssh -L 8080:target:80 user@host"},
        {"name":"SSL Tunnel","type":"concept","short":"Use TLS channels to tunnel arbitrary traffic.","install":"n/a","usage":"stunnel examples"},
        {"name":"SSTP","type":"protocol","short":"VPN over HTTPS used by Windows.","install":"n/a","usage":"Connect via SSTP client"},
        {"name":"L2TP","type":"protocol","short":"Layer2 tunneling often with IPSec.","install":"n/a","usage":"L2TP/IPSec setups"},
        {"name":"VPN Concentrator","type":"device","short":"Large-scale VPN aggregation device.","install":"n/a","usage":"Use for many remote users"},
        {"name":"Split Tunneling","type":"concept","short":"Decide which traffic goes via VPN vs direct.","install":"n/a","usage":"Use for performance vs security tradeoffs"}
      ]
    },
    {
      "name":"Network Security Commands",
      "children":[
        {"name":"fail2ban","type":"tool","short":"Log-based banning of attackers.","install":"sudo apt install fail2ban","usage":"sudo systemctl start fail2ban"},
        {"name":"ssh-keygen","type":"command","short":"Generate SSH keys for authentication.","install":"n/a","usage":"ssh-keygen -t rsa -b 4096"},
        {"name":"nmap scripting","type":"topic","short":"Nmap NSE se vulnerability checks kar sakte.","install":"sudo apt install nmap","usage":"nmap --script vuln target"},
        {"name":"iptables (security)","type":"command","short":"Firewall rules to secure host.","install":"n/a","usage":"iptables -A INPUT -p tcp --dport22 -j DROP"},
        {"name":"ufw rules","type":"command","short":"Simple firewall rules management.","install":"sudo apt install ufw","usage":"sudo ufw allow 443"},
        {"name":"auditd","type":"tool","short":"System audit daemon for security events.","install":"sudo apt install auditd","usage":"ausearch -ts today"},
        {"name":"chkrootkit","type":"tool","short":"Rootkit detection utility.","install":"sudo apt install chkrootkit","usage":"sudo chkrootkit"},
        {"name":"rkhunter","type":"tool","short":"Another rootkit scanning tool.","install":"sudo apt install rkhunter","usage":"sudo rkhunter --check"},
        {"name":"tripwire","type":"tool","short":"File integrity monitoring tool.","install":"sudo apt install tripwire","usage":"tripwire --check"},
        {"name":"ssh hardening","type":"topic","short":"Key auth, disable passwords, change port.","install":"n/a","usage":"Edit /etc/ssh/sshd_config"}
      ]
    },
    {
      "name":"Network Interview Q&A",
      "children":[
        {"name":"Q1: TCP vs UDP","type":"qa","short":"TCP reliable, connection-oriented; UDP lightweight.","install":"n/a","usage":"Explain use-cases like HTTP vs DNS"},
        {"name":"Q2: ARP vs RARP","type":"qa","short":"ARP IP->MAC, RARP MAC->IP (legacy).","install":"n/a","usage":"ARP for local resolution"},
        {"name":"Q3: Three-way handshake","type":"qa","short":"SYN, SYN-ACK, ACK — TCP connection setup.","install":"n/a","usage":"Explain sequence and flags"},
        {"name":"Q4: CSMA/CD","type":"qa","short":"Ethernet collision handling (historical).","install":"n/a","usage":"Explain how switches changed this"},
        {"name":"Q5: NAT types","type":"qa","short":"Static, dynamic, PAT (masquerading).","install":"n/a","usage":"Describe use for IPv4 shortage"},
        {"name":"Q6: Difference Layer2/Layer3 switch","type":"qa","short":"L2 switches forward by MAC, L3 can route IPs.","install":"n/a","usage":"Use-cases for each"},
        {"name":"Q7: What is MTU?","type":"qa","short":"Maximum Transmission Unit — largest packet size.","install":"n/a","usage":"Explain fragmentation"},
        {"name":"Q8: Explain BGP path selection","type":"qa","short":"Attributes like local-pref, AS-path, MED used.","install":"n/a","usage":"Simplified ranking explanation"},
        {"name":"Q9: How DNS resolution works","type":"qa","short":"Recursive resolver -> root -> TLD -> authoritative.","install":"n/a","usage":"Step-by-step flow"},
        {"name":"Q10: How to debug slow network","type":"qa","short":"Check latency, packet loss, interface errors.","install":"n/a","usage":"Use ping/mtr/tcpdump/iperf"}
      ]
    },
    {
      "name":"Misc Tools & Utilities",
      "children":[
        {"name":"netcat (nc)","type":"tool","short":"Swiss army networking tool for sockets.","install":"sudo apt install netcat","usage":"nc -l -p 1234"},
        {"name":"socat","type":"tool","short":"More powerful netcat for proxying.","install":"sudo apt install socat","usage":"socat TCP-LISTEN:80,fork ..."},
        {"name":"screen / tmux","type":"tool","short":"Session managers for long-running tasks.","install":"sudo apt install tmux screen","usage":"tmux new -s session"},
        {"name":"curl","type":"tool","short":"HTTP client for requests and testing.","install":"sudo apt install curl","usage":"curl -I https://example.com"},
        {"name":"wget","type":"tool","short":"Download files from web CLI.","install":"sudo apt install wget","usage":"wget http://example.com/file"},
        {"name":"telnet","type":"tool","short":"Test TCP connectivity to a port.","install":"sudo apt install telnet","usage":"telnet host 25"},
        {"name":"expect","type":"tool","short":"Automate interactive CLI sessions.","install":"sudo apt install expect","usage":"expect script usage"},
        {"name":"mtr","type":"tool","short":"(duplicate entry helpful) live traceroute+ping.","install":"sudo apt install mtr","usage":"mtr google.com"},
        {"name":"htop","type":"tool","short":"System processes and network stats overview.","install":"sudo apt install htop","usage":"htop"},
        {"name":"iftop","type":"tool","short":"Realtime per-connection bandwidth usage.","install":"sudo apt install iftop","usage":"sudo iftop -i eth0"}
      ]
    },
    {
      "name":"Logging & Forensics",
      "children":[
        {"name":"syslog","type":"concept","short":"System logging centralization for events.","install":"rsyslog or syslog-ng","usage":"Configure /etc/rsyslog.conf"},
        {"name":"Log Rotation","type":"topic","short":"Manage log sizes with logrotate.","install":"sudo apt install logrotate","usage":"/etc/logrotate.d configs"},
        {"name":"SIEM","type":"topic","short":"Security event aggregation and alerts.","install":"Splunk/ELK/QRadar","usage":"Send logs to SIEM"},
        {"name":"pcap Analysis","type":"topic","short":"Packet captures forensic analysis.","install":"wireshark/tshark","usage":"tshark -r capture.pcap"},
        {"name":"Audit Logs","type":"topic","short":"Track config changes and events.","install":"auditd","usage":"ausearch"},
        {"name":"Forensics Tools","type":"topic","short":"Analyze incidents and evidence preservation.","install":"volatility etc","usage":"Preserve images"},
        {"name":"Netflow/sFlow","type":"topic","short":"Network telemetry for traffic patterns.","install":"nfdump,pmacct","usage":"Collect flows from devices"},
        {"name":"Timestamps & Correlation","type":"topic","short":"Use consistent times for log correlation.","install":"n/a","usage":"Sync with NTP"},
        {"name":"Packet Carving","type":"topic","short":"Extract files from pcap for malware analysis.","install":"n/a","usage":"Use Wireshark export objects"},
        {"name":"Chain of Custody","type":"topic","short":"Preserve evidence integrity during investigation.","install":"n/a","usage":"Document actions and hashes"}
      ]
    },
    {
      "name":"Programming & Integration",
      "children":[
        {"name":"Socket Programming","type":"topic","short":"Raw sockets for custom protocols.","install":"n/a","usage":"Use Python's socket module"},
        {"name":"REST APIs","type":"topic","short":"Expose network info via web APIs.","install":"n/a","usage":"Build with Flask/FastAPI"},
        {"name":"gRPC","type":"topic","short":"Efficient RPC for service-to-service comms.","install":"pip install grpcio","usage":"Define proto and implement"},
        {"name":"SNMP Integration","type":"topic","short":"Pull device metrics using SNMP.","install":"pysnmp","usage":"snmpwalk -v2c"},
        {"name":"Telemetry (gNMI)","type":"topic","short":"Modern streaming telemetry for devices.","install":"n/a","usage":"Use collectors for metrics"},
        {"name":"Webhooks","type":"topic","short":"Event-driven notifications from network tools.","install":"n/a","usage":"Configure alerts to call endpoints"},
        {"name":"Netconf/YANG","type":"topic","short":"Model based config for routers/switches.","install":"n/a","usage":"Use with RESTCONF or NETCONF clients"},
        {"name":"SDKs (vendor)","type":"topic","short":"Use vendor SDKs for automation tasks.","install":"n/a","usage":"Cisco/Juniper SDK examples"},
        {"name":"Python + Pandas","type":"topic","short":"Analyze logs and metrics programmatically.","install":"pip install pandas","usage":"Parse CSVs and analyze"},
        {"name":"Webhook to Slack","type":"practice","short":"Send alerts to Slack via webhook.","install":"n/a","usage":"curl -X POST -H ..."}
      ]
    },
    {
      "name":"Architectures & Design",
      "children":[
        {"name":"High Availability","type":"topic","short":"Redundancy and failover design patterns.","install":"n/a","usage":"Active-passive or active-active"},
        {"name":"Scalability","type":"topic","short":"Design for growth in traffic and users.","install":"n/a","usage":"Load balancers, autoscaling"},
        {"name":"Multi-site Networking","type":"topic","short":"Connect multiple physical sites securely.","install":"n/a","usage":"VPNs or leased lines"},
        {"name":"DR & Backup","type":"topic","short":"Network designs for disaster recovery.","install":"n/a","usage":"Replicate critical services"},
        {"name":"Segmented Networks","type":"topic","short":"Microsegment for security and performance.","install":"n/a","usage":"VLANs + ACLs"},
        {"name":"Zero Trust Architecture","type":"topic","short":"Least privilege and continuous verification.","install":"n/a","usage":"Identity and access controls"},
        {"name":"Edge Networking","type":"topic","short":"Process data close to source for latency.","install":"n/a","usage":"Use CDN and edge compute"},
        {"name":"Hybrid Cloud Networking","type":"topic","short":"On-prem + cloud connect patterns.","install":"n/a","usage":"VPN/Direct Connect"},
        {"name":"Service Mesh","type":"topic","short":"Service-to-service networking in microservices.","install":"Istio/Linkerd","usage":"mTLS and traffic policies"},
        {"name":"Observability","type":"topic","short":"Metrics, logs, traces for whole system.","install":"n/a","usage":"Instrument apps and network"}
      ]
    },
    {
      "name":"Protocols Deep Dive",
      "children":[
        {"name":"TCP (details)","type":"topic","short":"Segmentation, retransmission, congestion control.","install":"n/a","usage":"Explain Reno/Cubic algorithms"},
        {"name":"UDP (details)","type":"topic","short":"No reliability — used for real-time apps.","install":"n/a","usage":"VoIP, DNS uses UDP"},
        {"name":"QUIC","type":"protocol","short":"Modern transport over UDP with TLS built-in.","install":"n/a","usage":"Used by HTTP/3"},
        {"name":"HTTP/2","type":"protocol","short":"Multiplexed connections for efficiency.","install":"n/a","usage":"Server push example"},
        {"name":"HTTP/3","type":"protocol","short":"Runs over QUIC for lower latency.","install":"n/a","usage":"Enable in modern browsers"},
        {"name":"SCTP","type":"protocol","short":"Message-oriented transport used in telecom.","install":"n/a","usage":"Carrier grade signalling"},
        {"name":"DHCP (details)","type":"protocol","short":"Discover, Offer, Request, ACK sequence.","install":"n/a","usage":"Trace DHCP handshake"},
        {"name":"TLS Handshake","type":"topic","short":"ClientHello, ServerHello, key exchange steps.","install":"n/a","usage":"openssl s_client debug"},
        {"name":"BGP attributes","type":"topic","short":"AS-path, local-pref, communities explain karo.","install":"n/a","usage":"Route selection example"},
        {"name":"ICMP Types","type":"topic","short":"Echo, destination unreachable types samjho.","install":"n/a","usage":"Use for diagnostics"}
      ]
    }
  ]
};

// Basic utility functions
function traverse(node, fn){
  fn(node);
  if(node.children) node.children.forEach(c=>traverse(c,fn));
}

// Build explanations list (flatten)
const flatList = [];
traverse(DATA, n=>{
  if(n.type || !n.children){
    flatList.push(n);
  }
});

// ---- UI Bindings ----
const svg = d3.select("#treeSvg");
const width = Math.max(800, document.querySelector("#treewrap").clientWidth);
const height = Math.max(640, document.querySelector("#treewrap").clientHeight);
svg.attr("viewBox", `0 0 ${width} ${height}`);

// zoom & pan
const g = svg.append("g");
const zoom = d3.zoom().scaleExtent([0.2, 3]).on("zoom", (event)=>g.attr("transform", event.transform));
svg.call(zoom);

// layout: horizontal collapsible tree
let root = d3.hierarchy(DATA);
root.x0 = height / 2;
root.y0 = 40;
const treeLayout = d3.tree().nodeSize([40, 200]);

// --- Collapse Function ---
function collapse(d) {
  if (d.children) {
    d._children = d.children;
    d._children.forEach(c => collapse(c));
    d.children = null;
  }
}

// --- Collapse All Initially ---
if (root.children) {
  root.children.forEach(c => collapse(c));  // collapse all top-level subtrees
}

update(root);  // now draw the collapsed view


// default expansions
function collapse(d){
  if(d.children){
    d._children = d.children;
    d._children.forEach(c=>collapse(c));
    d.children = null;
  }
}
function expandAll(){
  traverse(root, n=>{
    if(n._children){ n.children = n._children; n._children = null; }
  });
  update(root);
}
function collapseAll(){
  root.children.forEach(c=>collapse(c));
  update(root);
}
document.getElementById("expandAll").onclick = ()=>expandAll();
document.getElementById("collapseAll").onclick = ()=>collapseAll();

// theme toggle
document.getElementById("toggleTheme").onclick = ()=>{
  document.body.classList.toggle("theme-light");
};

// export JSON
document.getElementById("exportJson").onclick = ()=>{
  const blob = new Blob([JSON.stringify(DATA, null, 2)],{type:"application/json"});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "networking-master-data.json"; a.click();
  URL.revokeObjectURL(url);
};

// search
const searchInput = document.getElementById("search");
searchInput.addEventListener("input", (e)=>{
  const q = e.target.value.trim().toLowerCase();
  if(!q){ g.selectAll(".node").classed("dimmed", false).classed("highlight", false); return; }
  g.selectAll(".node").classed("dimmed", d=>{
    const name = d.data.name.toLowerCase();
    return !name.includes(q);
  }).classed("highlight", d=>{
    const name = d.data.name.toLowerCase();
    if(name.includes(q)){
      // bring into view (center)
      centerNode(d);
      return true;
    }
    return false;
  });
});

// center node in view
function centerNode(d){
  const transform = d3.zoomTransform(svg.node());
  const x = d.y, y = d.x;
  const svgCenterX = width/2, svgCenterY = height/2;
  const translate = [svgCenterX - x*transform.k, svgCenterY - y*transform.k];
  svg.transition().duration(600).call(zoom.transform, d3.zoomIdentity.translate(translate[0], translate[1]).scale(transform.k));
}

// update tree rendering
function update(source){
  const treeData = treeLayout(root);
  const nodes = treeData.descendants();
  const links = treeData.links();

  // set svg size dynamic
  const maxY = d3.max(nodes, d=>d.y) + 300;
  svg.attr("viewBox", `0 0 ${Math.max(width, maxY)} ${height}`);

  // LINKS
  const link = g.selectAll(".link").data(links, d=>d.target.data.name + d.target.depth);
  link.enter().append("path")
    .attr("class","link")
    .attr("d", d => diagonal(d))
    .merge(link)
    .transition().duration(350)
    .attr("d", d => diagonal(d));
  link.exit().remove();

  // NODES
  const node = g.selectAll(".node").data(nodes, d=>d.data.name + d.depth);
  const nodeEnter = node.enter().append("g").attr("class","node").attr("transform", d => `translate(${source.y0},${source.x0})`)
    .on("click", (event, d)=>{ nodeClick(d); update(d); })
    .on("mouseover", (event,d)=>showTooltip(event,d))
    .on("mouseout", hideTooltip);

  nodeEnter.append("circle").attr("r", 1e-6);
  nodeEnter.append("text").attr("dy", "0.31em").attr("x", d => d.children || d._children ? -12 : 12)
    .attr("text-anchor", d => d.children || d._children ? "end" : "start")
    .text(d => d.data.name)
    .clone(true).lower();

  // merge + transition
  const nodeUpdate = nodeEnter.merge(node);
  nodeUpdate.transition().duration(350).attr("transform", d=>`translate(${d.y},${d.x})`);
  nodeUpdate.select("circle").transition().attr("r", 8);
  nodeUpdate.select("text").style("fill-opacity",1);

  // exit
  const nodeExit = node.exit().transition().duration(350).attr("transform", d=>`translate(${source.y},${source.x})`).remove();
  nodeExit.select("circle").attr("r",1e-6);
  nodeExit.select("text").style("fill-opacity",1e-6);

  // save positions for transitions
  nodes.forEach(d => { d.x0 = d.x; d.y0 = d.y; });
}

// diagonal curve
function diagonal(d){
  const path = `M ${d.source.y} ${d.source.x}
                C ${(d.source.y + d.target.y) / 2} ${d.source.x},
                  ${(d.source.y + d.target.y) / 2} ${d.target.x},
                  ${d.target.y} ${d.target.x}`;
  return path;
}

// node click: toggle or show details
function nodeClick(d){
  if(d.children){
    d._children = d.children;
    d.children = null;
  } else if(d._children){
    d.children = d._children;
    d._children = null;
  } else {
    // leaf — show details
    showDetails(d.data);
  }
  update(d);
}

// Tooltip
const tooltip = d3.select("body").append("div").attr("class","tt").style("position","absolute").style("z-index",1000).style("pointer-events","none").style("padding","8px").style("background","rgba(2,6,23,0.9)").style("border-radius","6px").style("color","#cfe7ff").style("font-size","13px").style("display","none");
function showTooltip(event,d){
  if(!d.data) return;
  tooltip.style("display","block").html(`<strong>${d.data.name}</strong><div style="color:var(--muted);margin-top:6px">${d.data.short || ''}</div>`);
  const [x,y] = [event.pageX+12, event.pageY+12];
  tooltip.style("left", x+"px").style("top", y+"px");
}
function hideTooltip(){ tooltip.style("display","none"); }

// show details in right panel
function showDetails(data){
  document.getElementById("panelTitle").innerText = data.name || "";
  document.getElementById("panelShort").innerText = data.short || "—";
  document.getElementById("panelInstall").innerText = data.install || "—";
  document.getElementById("panelUsage").innerText = data.usage || "—";
  document.getElementById("panelUse").innerText = (data.short? data.short + " " : "") + (data.usage? "Usage: " + data.usage : "");
  // highlight explanation
  const list = document.querySelectorAll(".explainList .item");
  list.forEach(el => el.classList.remove("active"));
  const el = document.querySelector(`.explainList .item[data-name="${cssEscape(data.name)}"]`);
  if(el){
    el.classList.add("active");
    el.scrollIntoView({behavior:'smooth',block:'center'});
  }
}

// escape for querySelector attribute
function cssEscape(s){ return s.replace(/["\\]/g,'').replace(/\s/g,'_'); }

// build explanation list UI
const explainList = document.getElementById("explainList");
flatList.forEach(item=>{
  const el = document.createElement("div");
  el.className = "item";
  const key = cssEscape(item.name);
  el.setAttribute("data-name", key);
  el.innerHTML = `<strong>${item.name}</strong><div class="muted" style="margin-top:6px">${item.short || ''}</div>`;
  el.onclick = ()=>{ showDetails(item); };
  explainList.appendChild(el);
});

// populate learn paths (simple curated picks)
const beginner = ["OSI Model","IP Address","Ports","ping","ifconfig","Subnetting","HTTP","SSH","DNS","netstat"];
const intermediate = ["VLAN","NAT","iptables","tcpdump","Wireshark","OSPF","BGP","Nginx","Load Balancer","Prometheus"];
const advanced = ["BGP","MPLS","WireGuard","IPSec","Service Mesh","QUIC","Traffic Control (tc)","gNMI Telemetry","Automation (Ansible)","Observability"];

function populatePath(id, arr){
  const ol = document.getElementById(id);
  arr.forEach(name=>{
    const li = document.createElement("li");
    li.textContent = name;
    li.onclick = ()=> {
      // find node in flatList
      const found = flatList.find(n=>n.name === name);
      if(found) showDetails(found);
      // attempt to highlight and center any matching node on tree
      let foundNode = null;
      root.each(d=>{
        if(d.data.name === name) foundNode = d;
      });
      if(foundNode) centerNode(foundNode);
    };
    ol.appendChild(li);
  });
}
populatePath("pathBeginner", beginner);
populatePath("pathIntermediate", intermediate);
populatePath("pathAdvanced", advanced);

// keep everything collapsed initially
update(root);


// accessibility: keyboard search enter focuses first match
searchInput.addEventListener("keydown", (e)=>{
  if(e.key === "Enter"){
    const q = searchInput.value.trim().toLowerCase();
    if(!q) return;
    const found = flatList.find(n=>n.name.toLowerCase().includes(q));
    if(found) showDetails(found);
  }
});

// center root on load
setTimeout(()=> {
  // zoom to show central area
  svg.call(zoom.transform, d3.zoomIdentity.translate(80,20).scale(1));
}, 150);

// Simple CSS for tooltip and active explanation
const style = document.createElement('style');
style.innerHTML = `
.tt{box-shadow:0 10px 30px rgba(0,0,0,0.6);border-radius:8px}
.explainList .item.active{background:linear-gradient(90deg, rgba(77,166,255,0.06), transparent);border-radius:6px;padding:6px}
`;
document.head.appendChild(style);

// ensure responsiveness on resize
window.addEventListener("resize", ()=> {
  const w = Math.max(800, document.querySelector("#treewrap").clientWidth);
  svg.attr("viewBox", `0 0 ${w} ${height}`);
});
