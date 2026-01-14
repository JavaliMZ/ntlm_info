#!/usr/bin/env python3
import base64
import binascii
import math
import socket
import ssl
import struct
import sys
import time
from urllib.parse import urlparse
import http.client

# AV Pair Types
SERVER_NAME = 1
DOMAIN_NAME = 2
SERVER_FQDN = 3
DOMAIN_FQDN = 4
PARENT_DOMAIN = 5

REQ_FOR_CHALLENGE = "TlRMTVNTUAABAAAAFYIIYgAAAAAoAAAAAAAAACgAAAAAAAAAAAAAAA=="

REQ_FOR_CHALLENGE_BYTES = bytes([
    0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x15, 0x82, 0x08, 0x62,
    0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
])

class Type2Challenge:
    def __init__(self):
        self.raw = None
        self.server_name = ""
        self.domain_name = ""
        self.server_fqdn = ""
        self.domain_fqdn = ""
        self.parent_domain = ""
        self.os_version_number = ""
        self.os_version_string = ""

    def decode(self):
        raw = self.raw
        offset = struct.unpack("<H", raw[44:46])[0]
        data = raw[offset:]

        for _ in range(5):
            av_id, av_len = struct.unpack("<HH", data[:4])
            value = data[4:4 + av_len].replace(b"\x00", b"").decode(errors="ignore")

            if av_id == SERVER_NAME:
                self.server_name = value
            elif av_id == DOMAIN_NAME:
                self.domain_name = value
            elif av_id == SERVER_FQDN:
                self.server_fqdn = value
            elif av_id == DOMAIN_FQDN:
                self.domain_fqdn = value
            elif av_id == PARENT_DOMAIN:
                self.parent_domain = value

            data = data[4 + av_len:]

        if offset > 48:
            major, minor = raw[48], raw[49]
            build = struct.unpack("<H", raw[50:52])[0]
            self.os_version_number = f"{major}.{minor}.{build}"

            if major == 10:
                if build >= 26100:
                    self.os_version_string = f"Windows 11 / Server 2025 (Build {build})"
                elif build >= 22000:
                    self.os_version_string = f"Windows 11 / Server 2022 (Build {build})"
                elif build >= 20348:
                    self.os_version_string = f"Windows 10 / Server 2022 (Build {build})"
                elif build >= 17623:
                    self.os_version_string = f"Windows 10 / Server 2019 (Build {build})"
                else:
                    self.os_version_string = f"Windows 10 / Server 2016 (Build {build})"
            else:
                self.os_version_string = self.os_version_number

class Target:
    def __init__(self, url):
        self.url = urlparse(url)
        self.challenge = Type2Challenge()

    def get_challenge(self):
        scheme = self.url.scheme.lower()
        if scheme in ("http", "https"):
            self._get_http_challenge()
        elif scheme == "smb":
            self._get_smb_challenge()
        elif scheme == "rdp":
            self._get_rdp_challenge()
        elif scheme == "smtp":
            self._get_smtp_challenge()
        else:
            raise ValueError("Unsupported scheme")

        self.challenge.decode()

    def _get_http_challenge(self):
        port = self.url.port or (443 if self.url.scheme == "https" else 80)
        conn_cls = http.client.HTTPSConnection if self.url.scheme == "https" else http.client.HTTPConnection
        context = ssl._create_unverified_context()

        conn = conn_cls(self.url.hostname, port, context=context)
        headers = {"Authorization": f"NTLM {REQ_FOR_CHALLENGE}"}
        conn.request("GET", self.url.path or "/", headers=headers)
        resp = conn.getresponse()

        hdr = resp.getheader("WWW-Authenticate")
        if not hdr or "NTLM" not in hdr:
            raise RuntimeError("NTLM not supported")

        b64 = hdr.split("NTLM ")[1].split(",")[0]
        self.challenge.raw = base64.b64decode(b64)

    def _get_smb_challenge(self):
        host = self.url.hostname
        port = self.url.port or 445
        s = socket.create_connection((host, port), timeout=10)

        # SMB negotiate + NTLM request (same bytes as Go)
        s.sendall(REQ_FOR_CHALLENGE_BYTES)
        data = s.recv(4096)

        idx = data.find(b"NTLMSSP\x00")
        if idx == -1:
            raise RuntimeError("NTLM not supported over SMB")

        self.challenge.raw = data[idx:]

    def _get_rdp_challenge(self):
        host = self.url.hostname
        port = self.url.port or 3389

        raw_sock = socket.create_connection((host, port), timeout=10)
        context = ssl._create_unverified_context()
        sock = context.wrap_socket(raw_sock)

        nla = b"\x30\x37\xa0\x03\x02\x01\x60\xa1\x30\x30\x2e\x30\x2c\xa0\x2a\x04\x28" + REQ_FOR_CHALLENGE_BYTES
        sock.sendall(nla)
        data = sock.recv(4096)

        self.challenge.raw = data

    def _get_smtp_challenge(self):
        host = self.url.hostname
        port = self.url.port or 25

        s = socket.create_connection((host, port), timeout=10)
        s.recv(1024)
        s.sendall(b"EHLO test\r\n")
        resp = s.recv(2048)

        if b"NTLM" not in resp:
            raise RuntimeError("SMTP NTLM not supported")

        s.sendall(f"AUTH NTLM {REQ_FOR_CHALLENGE}\r\n".encode())
        resp = s.recv(4096)
        b64 = resp.split(b" ")[1].strip()
        self.challenge.raw = base64.b64decode(b64)

    def print_info(self):
        c = self.challenge
        width = max(45, len(self.url.geturl()))
        fmt = f"| {{:<17}} | {{:<{width}}} |"
        print("+" + "-"*19 + "+" + "-"*(width+2) + "+")
        print(fmt.format("URL", self.url.geturl()))
        print("+" + "-"*19 + "+" + "-"*(width+2) + "+")
        print(fmt.format("Server Name", c.server_name))
        print(fmt.format("Domain Name", c.domain_name))
        print(fmt.format("Server FQDN", c.server_fqdn))
        print(fmt.format("Domain FQDN", c.domain_fqdn))
        print(fmt.format("Parent Domain", c.parent_domain))
        print(fmt.format("OS Version", c.os_version_string))
        print("+" + "-"*19 + "+" + "-"*(width+2) + "+")

def main():
    import sys
    
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <url>")
        sys.exit(1)

    target = Target(sys.argv[1])
    target.get_challenge()
    target.print_info()
