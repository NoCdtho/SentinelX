def get_field(fields: dict, field_name: str, default: str = "N/A") -> str:
    """Safely retrieve and format a TShark field value."""
    value = fields.get(field_name)

    if value is None:
        return default
    if isinstance(value, list):
        return ", ".join(str(x) for x in value) if value else default

    return str(value)


def parse_packet(raw_packet: dict, packet_number: int) -> dict:
    """Convert raw nested TShark JSON to a structured summary object."""
    layers = raw_packet.get("_source", {}).get("layers", {})

    frame = layers.get("frame", {})
    ip = layers.get("ip", {})
    ipv6 = layers.get("ipv6", {})
    tcp = layers.get("tcp", {})
    udp = layers.get("udp", {})
    dns = layers.get("dns", {})
    icmp = layers.get("icmp", {})
    arp = layers.get("arp", {})

    source = (
        get_field(ip, "ip.src", "N/A")
        if ip
        else get_field(ipv6, "ipv6.src", "N/A")
    )

    destination = (
        get_field(ip, "ip.dst", "N/A")
        if ip
        else get_field(ipv6, "ipv6.dst", "N/A")
    )

    packet = {
        "packet_number": packet_number,
        "timestamp": get_field(frame, "frame.time", "N/A"),
        "epoch_time": get_field(frame, "frame.time_epoch", "N/A"),
        "length": get_field(frame, "frame.len", "N/A"),
        "captured_length": get_field(frame, "frame.cap_len", "N/A"),
        "protocol_stack": get_field(frame, "frame.protocols", "Unknown"),
        "source_ip": source,
        "destination_ip": destination,
        "tcp": {},
        "udp": {},
        "dns": {},
        "icmp": {},
        "arp": {}
    }

    if tcp:
        packet["tcp"] = {
            "source_port": get_field(tcp, "tcp.srcport"),
            "destination_port": get_field(tcp, "tcp.dstport"),
            "flags": get_field(tcp, "tcp.flags.str"),
            "flags_hex": get_field(tcp, "tcp.flags"),
            "sequence": get_field(tcp, "tcp.seq"),
            "acknowledgement": get_field(tcp, "tcp.ack")
        }

    if udp:
        packet["udp"] = {
            "source_port": get_field(udp, "udp.srcport"),
            "destination_port": get_field(udp, "udp.dstport"),
            "length": get_field(udp, "udp.length")
        }

    if dns:
        packet["dns"] = {
            "transaction_id": get_field(dns, "dns.id"),
            "flags": get_field(dns, "dns.flags"),
            "queries": get_field(dns, "dns.qry.name"),
            "response": get_field(dns, "dns.flags.response")
        }

    if icmp:
        packet["icmp"] = {
            "type": get_field(icmp, "icmp.type"),
            "code": get_field(icmp, "icmp.code")
        }

    if arp:
        packet["arp"] = {
            "opcode": get_field(arp, "arp.opcode"),
            "sender_mac": get_field(arp, "arp.src.hw_mac"),
            "sender_ip": get_field(arp, "arp.src.proto_ipv4"),
            "target_mac": get_field(arp, "arp.dst.hw_mac"),
            "target_ip": get_field(arp, "arp.dst.proto_ipv4")
        }

    return packet