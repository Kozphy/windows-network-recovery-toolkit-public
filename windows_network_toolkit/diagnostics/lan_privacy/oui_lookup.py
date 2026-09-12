"""MAC OUI vendor lookup — embedded prefix table for home/SOHO devices.

Module responsibility:
    Map normalized MAC prefixes to vendor name and IoT-like flag from a curated
    OUI subset (not the full IEEE registry).

System placement:
    Used by ``lan_privacy.collectors`` when enriching inventory device rows.

Key invariants:
    * Unknown OUIs return empty vendor — flagged as ``unknown_vendor`` upstream.
    * Table is portfolio subset; absence of a prefix is not proof of legitimacy.
    * Lookup is case- and separator-normalized on the first three octets.

Side effects:
    * None — in-memory dict lookup only.
"""

from __future__ import annotations

# Common OUIs (first 3 octets) — portfolio subset, not exhaustive IEEE registry.
OUI_TABLE: dict[str, tuple[str, bool]] = {
    "00:1A:2B": ("Apple, Inc.", True),
    "3C:22:FB": ("Apple, Inc.", True),
    "AC:DE:48": ("Apple, Inc.", True),
    "B8:27:EB": ("Raspberry Pi Foundation", True),
    "DC:A6:32": ("Raspberry Pi Trading Ltd", True),
    "18:B4:30": ("Google, Inc.", True),
    "54:60:09": ("Google, Inc.", True),
    "F4:F5:D8": ("Google, Inc.", True),
    "00:17:88": ("Philips Lighting BV", True),
    "B0:7F:1D": ("Amazon Technologies Inc.", True),
    "44:65:0D": ("Amazon Technologies Inc.", True),
    "50:DC:E7": ("Amazon Technologies Inc.", True),
    "00:1B:44": ("Samsung Electronics Co.,Ltd", True),
    "5C:49:7D": ("Samsung Electronics Co.,Ltd", True),
    "CC:B1:1A": ("Samsung Electronics Co.,Ltd", True),
    "D8:31:34": ("Roku, Inc.", True),
    "B0:A7:37": ("Roku, Inc.", True),
    "00:0C:29": ("VMware, Inc.", True),
    "00:50:56": ("VMware, Inc.", True),
    "00:1E:65": ("Intel Corporate", True),
    "00:1F:3B": ("Intel Corporate", True),
    "F8:34:41": ("Xiaomi Communications Co Ltd", True),
    "28:6C:07": ("Xiaomi Communications Co Ltd", True),
    "00:14:22": ("Dell Inc.", True),
    "F8:BC:12": ("Dell Inc.", True),
    "00:25:90": ("Super Micro Computer, Inc.", True),
    "E4:5F:01": ("Raspberry Pi Trading Ltd", True),
    "00:0F:B0": ("Netgear", True),
    "20:E5:2A": ("Netgear", True),
    "C4:04:15": ("Netgear", True),
    "00:1D:0F": ("TP-Link Technologies Co.,Ltd.", True),
    "50:C7:BF": ("TP-Link Technologies Co.,Ltd.", True),
    "00:27:19": ("TP-Link Technologies Co.,Ltd.", True),
    "00:1A:70": ("ASUSTek COMPUTER INC.", True),
    "04:D4:C4": ("ASUSTek COMPUTER INC.", True),
    "00:24:B2": ("Cisco Systems, Inc", True),
    "00:1E:13": ("Cisco-Linksys, LLC", True),
}

IOT_VENDOR_HINTS = frozenset(
    {
        "Roku",
        "Samsung",
        "Amazon",
        "Google",
        "Philips",
        "Xiaomi",
        "TP-Link",
        "Netgear",
    }
)


def normalize_mac(mac: str) -> str:
    """Normalize a MAC address string to an upper-case, colon-separated prefix.

    Strips whitespace, converts hyphens to colons, and upper-cases the result.
    Returns the first three octets (OUI prefix) for table lookup.

    Args:
        mac: Raw MAC address string in any common format
            (e.g. ``"b8:27:eb:aa:bb:cc"``, ``"B8-27-EB-AA-BB-CC"``).

    Returns:
        Upper-case colon-separated OUI prefix (e.g. ``"B8:27:EB"``), or the
        normalized full string when fewer than 3 octets are present.
    """
    m = (mac or "").strip().upper().replace("-", ":")
    parts = m.split(":")
    if len(parts) >= 3:
        return ":".join(parts[:3])
    return m


def lookup_vendor(mac: str) -> tuple[str, bool]:
    """Look up the OUI vendor for a MAC address using the embedded prefix table.

    Args:
        mac: Raw MAC address string (any standard format).

    Returns:
        A 2-tuple of:
            vendor_name (str): Human-readable vendor name, or ``"Unknown"`` when
                the OUI prefix is present in neither the table nor the 3-octet key.
                Empty string when the MAC is blank or too short.
            vendor_known (bool): ``True`` only when the prefix is in ``OUI_TABLE``.
    """
    prefix = normalize_mac(mac)
    if not prefix or len(prefix) < 8:
        return ("", False)
    # Match first 3 octets
    key = ":".join(prefix.split(":")[:3])
    if key in OUI_TABLE:
        name, known = OUI_TABLE[key]
        return (name, known)
    return ("Unknown", False)


def is_iot_like_vendor(vendor: str) -> bool:
    """Return True if the vendor name matches a known IoT/consumer device hint.

    Checks ``IOT_VENDOR_HINTS`` as case-insensitive substring matches.
    Used to flag devices that are likely IoT or consumer media devices
    (e.g. Roku, Samsung, Amazon Echo, Google Nest).

    Args:
        vendor: Vendor name string from ``lookup_vendor``.

    Returns:
        ``True`` if any IoT vendor hint substring is found in the vendor name.
    """
    v = (vendor or "").lower()
    return any(h.lower() in v for h in IOT_VENDOR_HINTS)
