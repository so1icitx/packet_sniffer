
icmp_type_3_codes = {
    0: "Network Unreachable",
    1: "Host Unreachable",
    2: "Protocol Unreachable",
    3: "Port Unreachable",
    4: "Fragmentation Needed",
    5: "Source Route Failed",
    6: "Destination Network Unknown",
    7: "Destination Host Unknown",
    8: "Source Host Isolated (Obsolete)",
    9: "Destination Network Prohibited",
    10: "Destination Host Prohibited",
    11: "Network Unreachable for TOS",
    12: "Host Unreachable for TOS",
    13: "Communication Prohibited"
}
for i in icmp_type_3_codes:
    print(i)
