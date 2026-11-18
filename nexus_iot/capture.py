"""Passive, dependency-free readers for classic PCAP and PCAPNG captures.

``packets()`` decodes only packet headers; its records never retain or print payload bytes.
``tcp_segments()`` is a separate reader that returns TCP payload bytes for protocol decoders
such as ``mqtt.py``.
Supported link layers: Ethernet, raw IP, and Linux cooked v1/v2.
"""
from __future__ import annotations

import ipaddress
import struct
from pathlib import Path
from typing import BinaryIO, Callable, Iterator


class CaptureError(ValueError):
    pass


def packets(path: Path, aggregate_seconds: float = 0.0) -> Iterator[dict]:
    """Yield packet header records, optionally coalesced by flow in time buckets."""
    with path.open("rb") as stream:
        magic=stream.read(4);stream.seek(0)
        source=_pcapng(stream,path.name) if magic == b"\x0a\x0d\x0d\x0a" else _pcap(stream,path.name)
        yield from _aggregate(source,aggregate_seconds) if aggregate_seconds>0 else source


def _aggregate(source: Iterator[dict], seconds: float) -> Iterator[dict]:
    """Bound memory to one timestamp bucket and summarize repeated header flows."""
    bucket=None;groups={}
    for packet in source:
        current=int(packet["timestamp"]//seconds)
        if bucket is not None and current!=bucket:
            yield from groups.values();groups={}
        bucket=current
        key=(current,packet.get("event"),packet.get("source_ip"),packet.get("destination_ip"),
             packet.get("protocol"),packet.get("source_port"),packet.get("destination_port"),packet.get("linktype"))
        row=groups.get(key)
        if row is None:
            row=dict(packet);row["packet_count"]=1;row["timestamp_start"]=packet["timestamp"];row["timestamp_end"]=packet["timestamp"]
            groups[key]=row
        else:
            row["packet_count"]+=1;row["timestamp_start"]=min(row["timestamp_start"],packet["timestamp"])
            row["timestamp_end"]=max(row["timestamp_end"],packet["timestamp"]);row["wire_bytes"]+=packet.get("wire_bytes",0)
    yield from groups.values()


def _pcap(stream: BinaryIO, filename: str, decoder: Callable[..., dict | None] | None = None) -> Iterator[dict | None]:
    decoder = decoder or _decode
    header=stream.read(24)
    if len(header) < 24:
        raise CaptureError("truncated PCAP global header")
    magic = header[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if magic not in formats:
        raise CaptureError("unsupported or invalid PCAP magic (expected classic PCAP or PCAPNG)")
    endian, resolution = formats[magic]
    _, _, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", header[4:24])
    index=0
    while True:
        record=stream.read(16)
        if not record: break
        if len(record)<16: raise CaptureError(f"truncated packet header at packet {index+1}")
        sec, frac, caplen, wirelen = struct.unpack(endian + "IIII", record)
        if caplen > snaplen: raise CaptureError(f"invalid packet length at packet {index+1}")
        frame=stream.read(caplen)
        if len(frame)!=caplen: raise CaptureError(f"truncated packet {index+1}")
        index += 1
        yield decoder(frame, sec + frac/resolution, linktype, filename, index, wirelen)


def _pcapng(stream: BinaryIO, filename: str, decoder: Callable[..., dict | None] | None = None) -> Iterator[dict | None]:
    decoder = decoder or _decode
    endian, interfaces, index = None, [], 0
    while True:
        offset=stream.tell();block_head=stream.read(8)
        if not block_head: break
        if len(block_head)<8: raise CaptureError(f"truncated PCAPNG block at byte {offset}")
        block_type_raw = block_head[:4]
        if block_type_raw == b"\x0a\x0d\x0d\x0a":
            bom=stream.read(4)
            if len(bom)<4: raise CaptureError("truncated section header")
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">" if bom == b"\x1a\x2b\x3c\x4d" else None
            if endian is None: raise CaptureError("invalid PCAPNG byte-order magic")
            interfaces = []
            block_len=struct.unpack(endian+"I",block_head[4:8])[0]
            block_type=0x0A0D0D0A
            body_prefix=b""
            remaining=block_len-16
        if endian is None: raise CaptureError("PCAPNG must begin with a section header")
        if block_type_raw != b"\x0a\x0d\x0d\x0a":
            block_type,block_len=struct.unpack(endian+"II",block_head)
            remaining=block_len-12;body_prefix=b""
        if block_len<12 or remaining<0: raise CaptureError(f"invalid PCAPNG block at byte {offset}")
        body=stream.read(remaining)
        trailer_bytes=stream.read(4)
        if len(body)!=remaining or len(trailer_bytes)!=4: raise CaptureError(f"truncated PCAPNG block at byte {offset}")
        block=body_prefix+body if body_prefix else body
        trailer, = struct.unpack(endian + "I", trailer_bytes)
        if trailer != block_len: raise CaptureError(f"PCAPNG block length mismatch at byte {offset}")
        if block_type == 1:  # Interface Description Block
            if len(block) < 8: raise CaptureError("truncated PCAPNG interface description")
            linktype = struct.unpack(endian + "H", block[:2])[0]
            resolution = 1_000_000; timestamp_offset=0
            pos = 8
            while pos + 4 <= len(block):
                code, length = struct.unpack(endian + "HH", block[pos:pos+4]); pos += 4
                if code == 0: break
                value = block[pos:pos+length]
                if code == 9 and value:
                    b = value[0]; resolution = (2 ** (b & 0x7f)) if b & 0x80 else (10 ** b)
                if code == 14 and length == 8:
                    timestamp_offset=struct.unpack(endian+"q",value)[0]
                pos += (length + 3) & ~3
                if pos>len(block): raise CaptureError("invalid PCAPNG interface option length")
            interfaces.append((linktype, resolution,timestamp_offset))
        elif block_type == 6:  # Enhanced Packet Block
            if len(block) < 20: raise CaptureError("truncated PCAPNG enhanced packet block")
            iid, high, low, caplen, wirelen = struct.unpack(endian + "IIIII", block[:20])
            if iid >= len(interfaces): raise CaptureError("PCAPNG packet references an unknown interface")
            if 20 + caplen > len(block): raise CaptureError("truncated PCAPNG packet data")
            linktype, resolution, timestamp_offset = interfaces[iid]; index += 1
            ticks = (high << 32) | low
            yield decoder(block[20:20+caplen], ticks/resolution+timestamp_offset, linktype, filename, index, wirelen)
        elif block_type == 2:  # Obsolete Packet Block
            if len(block)<20: raise CaptureError("truncated PCAPNG packet block")
            iid,_,high,low,caplen,wirelen=struct.unpack(endian+"HHIIII",block[:20])
            if iid>=len(interfaces): raise CaptureError("PCAPNG packet references an unknown interface")
            if 20+caplen>len(block): raise CaptureError("truncated PCAPNG packet data")
            linktype,resolution,timestamp_offset=interfaces[iid];index+=1
            ticks=(high<<32)|low
            yield decoder(block[20:20+caplen],ticks/resolution+timestamp_offset,linktype,filename,index,wirelen)
        elif block_type == 3:  # Simple Packet Block has no timestamp.
            raise CaptureError("PCAPNG Simple Packet Blocks have no timestamp and cannot be placed on the incident timeline")


def _link_layer(frame: bytes, linktype: int, index: int) -> tuple[int | None, int] | None:
    """Return (ethertype, network-layer offset), or None for an unsupported link type."""
    pos, ethertype = 0, None
    if linktype == 1:  # Ethernet
        if len(frame) < 14: raise CaptureError(f"packet {index}: truncated Ethernet header")
        ethertype = int.from_bytes(frame[12:14], "big"); pos = 14
        while ethertype in (0x8100, 0x88A8):
            if len(frame) < pos+4: raise CaptureError(f"packet {index}: truncated VLAN header")
            ethertype = int.from_bytes(frame[pos+2:pos+4], "big"); pos += 4
    elif linktype == 101:  # raw IP
        if not frame: raise CaptureError(f"packet {index}: empty raw-IP frame")
        ethertype = 0x0800 if frame[0] >> 4 == 4 else 0x86DD if frame[0] >> 4 == 6 else None
    elif linktype == 113:  # Linux cooked v1
        if len(frame) < 16: raise CaptureError(f"packet {index}: truncated cooked header")
        ethertype = int.from_bytes(frame[14:16], "big"); pos = 16
    elif linktype == 276:  # Linux cooked v2
        if len(frame)<20: raise CaptureError(f"packet {index}: truncated cooked-v2 header")
        ethertype=int.from_bytes(frame[:2],"big");pos=20
    else:
        return None
    return ethertype, pos


def _ip_layer(frame: bytes, pos: int, ethertype: int | None, index: int) -> dict:
    """Decode the IPv4/IPv6 header at pos.

    Returns source/destination text, transport protocol number, transport offset ``l4``,
    ``ip_end`` (end of the IP datagram according to its length field, which excludes
    link-layer padding), and fragment flags.
    """
    source = destination = "?"; can_parse_transport=True; is_fragment=False
    if ethertype == 0x0800:
        if len(frame) < pos+20: raise CaptureError(f"packet {index}: truncated IPv4 header")
        ihl = (frame[pos] & 15)*4
        if ihl < 20 or len(frame) < pos+ihl: raise CaptureError(f"packet {index}: invalid IPv4 header length")
        source = str(ipaddress.ip_address(frame[pos+12:pos+16])); destination = str(ipaddress.ip_address(frame[pos+16:pos+20]))
        frag=struct.unpack(">H",frame[pos+6:pos+8])[0]
        fragment_offset=frag&0x1fff;is_fragment=bool(fragment_offset or frag&0x2000)
        can_parse_transport=fragment_offset==0
        proto_num = frame[pos+9]; l4 = pos+ihl
        total_length = struct.unpack(">H",frame[pos+2:pos+4])[0]
        # A zero total length appears in captures of segmentation-offloaded packets.
        ip_end = pos+total_length if total_length else len(frame)
    elif ethertype == 0x86DD:
        if len(frame) < pos+40: raise CaptureError(f"packet {index}: truncated IPv6 header")
        source = str(ipaddress.ip_address(frame[pos+8:pos+24])); destination = str(ipaddress.ip_address(frame[pos+24:pos+40]))
        proto_num = frame[pos+6]; l4 = pos+40
        payload_length = struct.unpack(">H",frame[pos+4:pos+6])[0]
        ip_end = pos+40+payload_length if payload_length else len(frame)
        # Walk common IPv6 extension headers to find the transport header.
        while proto_num in (0,43,44,51,60,135):
            if proto_num==44:
                if len(frame)<l4+8: raise CaptureError(f"packet {index}: truncated IPv6 fragment header")
                frag=struct.unpack(">H",frame[l4+2:l4+4])[0]
                is_fragment=True
                if (frag>>3)&0x1fff: can_parse_transport=False
                next_proto=frame[l4];ext_len=8
            else:
                if len(frame)<l4+2: raise CaptureError(f"packet {index}: truncated IPv6 extension header")
                next_proto=frame[l4]
                ext_len=(frame[l4+1]+2)*4 if proto_num==51 else (frame[l4+1]+1)*8
                if len(frame)<l4+ext_len: raise CaptureError(f"packet {index}: invalid IPv6 extension length")
            proto_num=next_proto;l4+=ext_len
    else:
        proto_num, l4, ip_end = -1, len(frame), len(frame)
    return {"source": source, "destination": destination, "proto_num": proto_num, "l4": l4, "ip_end": ip_end,
            "can_parse_transport": can_parse_transport, "is_fragment": is_fragment}


def _decode(frame: bytes, timestamp: float, linktype: int, filename: str, index: int, wirelen: int) -> dict:
    link = _link_layer(frame, linktype, index)
    if link is None:
        return {"timestamp": timestamp, "event": "unsupported_link_packet", "capture": filename,
                "packet": index, "linktype": linktype, "wire_bytes": wirelen}
    ip = _ip_layer(frame, link[1], link[0], index)
    source, destination, proto_num, l4 = ip["source"], ip["destination"], ip["proto_num"], ip["l4"]
    sport = dport = None
    proto = {6:"tcp", 17:"udp", 1:"icmp", 58:"icmpv6"}.get(proto_num, "other")
    if ip["can_parse_transport"] and proto in ("tcp", "udp") and len(frame) >= l4+4:
        sport, dport = struct.unpack(">HH", frame[l4:l4+4])
    return {"timestamp": timestamp, "event": "network_packet", "capture": filename,
            "packet": index, "source_ip": source, "destination_ip": destination,
            "protocol": proto, "source_port": sport, "destination_port": dport,
            "wire_bytes": wirelen,"is_fragment":ip["is_fragment"]}


TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04


def tcp_segments(path: Path) -> Iterator[dict]:
    """Yield one record per captured TCP segment, including its payload bytes.

    This is a separate reader for protocol decoders (see ``mqtt.py``); ``packets()`` still
    returns header summaries only. Non-TCP packets, unsupported link types, and non-initial
    IP fragments are skipped. Each record has ``timestamp``, ``packet`` (1-based index in the
    capture), ``source_ip``, ``source_port``, ``destination_ip``, ``destination_port``,
    ``seq`` (TCP sequence number), ``flags`` (TCP flag bits), ``payload`` (bytes) and
    ``truncated`` (True when the capture snap length cut off part of the segment payload).
    Raises CaptureError for a corrupt capture, like ``packets()``.
    """
    with path.open("rb") as stream:
        magic=stream.read(4);stream.seek(0)
        reader=_pcapng if magic == b"\x0a\x0d\x0d\x0a" else _pcap
        for segment in reader(stream,path.name,_decode_tcp_segment):
            if segment is not None: yield segment


def _decode_tcp_segment(frame: bytes, timestamp: float, linktype: int, filename: str, index: int, wirelen: int) -> dict | None:
    """Decode a frame to a TCP segment record, or None when it is not a parseable TCP segment."""
    link = _link_layer(frame, linktype, index)
    if link is None:
        return None
    ip = _ip_layer(frame, link[1], link[0], index)
    if ip["proto_num"] != 6 or not ip["can_parse_transport"] or ip["is_fragment"]:
        return None
    l4 = ip["l4"]
    if len(frame) < l4 + 20:
        return None
    sport, dport, seq, _ack, offset_flags = struct.unpack(">HHIIH", frame[l4:l4+14])
    header_len = (offset_flags >> 12) * 4
    if header_len < 20:
        return None
    start = l4 + header_len
    end = ip["ip_end"] if ip["ip_end"] >= start else start
    return {"timestamp": timestamp, "packet": index, "capture": filename,
            "source_ip": ip["source"], "destination_ip": ip["destination"],
            "source_port": sport, "destination_port": dport, "seq": seq, "flags": offset_flags & 0x3F,
            "payload": bytes(frame[start:end]), "truncated": end > len(frame)}
