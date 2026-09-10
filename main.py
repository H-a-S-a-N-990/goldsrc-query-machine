from flask import Flask, request, render_template_string
import socket
import struct
import time

app = Flask(__name__)

# ============================================================
# CONFIG
# ============================================================

DEFAULT_TIMEOUT = 3.0


# ============================================================
# BASIC UDP
# ============================================================

def make_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(DEFAULT_TIMEOUT)
    return sock


def send_recv(sock, target, packet, timeout=DEFAULT_TIMEOUT):
    sock.settimeout(timeout)

    start = time.time()

    try:
        sock.sendto(packet, target)
        data, addr = sock.recvfrom(65535)

        ping = (time.time() - start) * 1000.0

        return data, ping, addr

    except Exception as e:
        return None, None, str(e)


# ============================================================
# STRING HELPERS
# ============================================================

def read_cstring(data, pos):
    if pos >= len(data):
        return "", len(data)

    end = data.find(b"\x00", pos)

    if end == -1:
        return data[pos:].decode("utf-8", errors="replace"), len(data)

    return data[pos:end].decode("utf-8", errors="replace"), end + 1


def safe_u8(data, pos):
    if pos >= len(data):
        return 0, pos + 1

    return data[pos], pos + 1


def safe_i32(data, pos):
    if pos + 4 > len(data):
        return 0, pos + 4

    return struct.unpack_from("<i", data, pos)[0], pos + 4


def safe_u16(data, pos):
    if pos + 2 > len(data):
        return 0, pos + 2

    return struct.unpack_from("<H", data, pos)[0], pos + 2


def safe_u32(data, pos):
    if pos + 4 > len(data):
        return 0, pos + 4

    return struct.unpack_from("<I", data, pos)[0], pos + 4


def safe_float(data, pos):
    if pos + 4 > len(data):
        return 0.0, pos + 4

    return struct.unpack_from("<f", data, pos)[0], pos + 4


# ============================================================
# SPLIT PACKET REASSEMBLY
# ============================================================

def receive_response(sock, first_packet, target):
    """
    Handles normal GoldSrc/A2S packets.

    Also attempts to reassemble common split packets.
    """

    if not first_packet:
        return None

    # Normal packet
    if first_packet[:4] == b"\xff\xff\xff\xff":
        return first_packet

    # Common split packet header:
    #
    # FF FF FF FE
    # packet ID
    # total / number
    #
    if first_packet[:4] != b"\xff\xff\xff\xfe":
        return first_packet

    packets = [first_packet]

    try:
        header = first_packet

        if len(header) < 9:
            return first_packet

        packet_id = header[4:8]
        packet_info = header[8]

        total = packet_info & 0x0F

        if total <= 1:
            return first_packet[9:]

        pieces = {}

        # First packet
        index = (packet_info >> 4) & 0x0F
        pieces[index] = first_packet[9:]

        sock.settimeout(DEFAULT_TIMEOUT)

        while len(pieces) < total:

            data, addr = sock.recvfrom(65535)

            if data[:4] != b"\xff\xff\xff\xfe":
                continue

            if len(data) < 9:
                continue

            if data[4:8] != packet_id:
                continue

            info = data[8]

            idx = (info >> 4) & 0x0F

            pieces[idx] = data[9:]

        result = b""

        for i in range(total):
            result += pieces.get(i, b"")

        return result

    except Exception:
        return first_packet


# ============================================================
# LEGACY GOLD-SRC INFO
# ============================================================

def parse_legacy_info(data):

    result = {
        "response_type": "0x6D",
        "address": "",
        "name": "",
        "map": "",
        "folder": "",
        "game": "",
        "players": 0,
        "maxplayers": 0,
        "protocol": 0,
        "type": "",
        "os": "",
        "password": False,
        "mod": False,
        "vac": False,
        "bots": 0
    }

    if len(data) < 6:
        return result

    if data[:5] != b"\xff\xff\xff\xff\x6d":
        return result

    pos = 5

    result["address"], pos = read_cstring(data, pos)
    result["name"], pos = read_cstring(data, pos)
    result["map"], pos = read_cstring(data, pos)
    result["folder"], pos = read_cstring(data, pos)
    result["game"], pos = read_cstring(data, pos)

    result["players"], pos = safe_u8(data, pos)
    result["maxplayers"], pos = safe_u8(data, pos)
    result["protocol"], pos = safe_u8(data, pos)

    if pos < len(data):
        result["type"] = chr(data[pos])
        pos += 1

    if pos < len(data):
        result["os"] = chr(data[pos])
        pos += 1

    password, pos = safe_u8(data, pos)
    result["password"] = bool(password)

    modded, pos = safe_u8(data, pos)
    result["mod"] = bool(modded)

    # If modded, additional fields exist
    if modded:

        # Website
        _, pos = read_cstring(data, pos)

        # Download URL
        _, pos = read_cstring(data, pos)

        # Mod null terminator
        if pos < len(data):
            pos += 1

        # Mod version
        _, pos = safe_u32(data, pos)

        # Mod size
        _, pos = safe_u32(data, pos)

        # Mod type
        _, pos = safe_u8(data, pos)

        # DLL
        _, pos = safe_u8(data, pos)

    # VAC / secure
    if pos < len(data):
        vac, pos = safe_u8(data, pos)
        result["vac"] = bool(vac)

    # Bots
    if pos < len(data):
        result["bots"], pos = safe_u8(data, pos)

    return result


# ============================================================
# MODERN A2S INFO
# ============================================================

def parse_modern_info(data):

    result = {
        "response_type": "0x49",
        "address": "",
        "name": "",
        "map": "",
        "folder": "",
        "game": "",
        "players": 0,
        "maxplayers": 0,
        "bots": 0,
        "protocol": 0,
        "type": "",
        "os": "",
        "password": False,
        "vac": False
    }

    if len(data) < 6:
        return result

    if data[:5] != b"\xff\xff\xff\xff\x49":
        return result

    pos = 5

    # Protocol
    result["protocol"], pos = safe_u8(data, pos)

    result["name"], pos = read_cstring(data, pos)
    result["map"], pos = read_cstring(data, pos)
    result["folder"], pos = read_cstring(data, pos)
    result["game"], pos = read_cstring(data, pos)

    # App ID
    _, pos = safe_u16(data, pos)

    result["players"], pos = safe_u8(data, pos)
    result["maxplayers"], pos = safe_u8(data, pos)
    result["bots"], pos = safe_u8(data, pos)

    if pos < len(data):
        result["type"] = chr(data[pos])
        pos += 1

    if pos < len(data):
        result["os"] = chr(data[pos])
        pos += 1

    password, pos = safe_u8(data, pos)
    result["password"] = bool(password)

    vac, pos = safe_u8(data, pos)
    result["vac"] = bool(vac)

    return result


# ============================================================
# INFO QUERY
# ============================================================

def query_info(sock, target):

    # --------------------------------------------------------
    # Modern A2S_INFO
    # --------------------------------------------------------

    request_packet = (
        b"\xff\xff\xff\xff"
        b"\x54"
        b"Source Engine Query\x00"
    )

    data, ping, addr = send_recv(sock, target, request_packet)

    if data:

        full = receive_response(sock, data, target)

        if full and full[:5] == b"\xff\xff\xff\xff\x49":
            info = parse_modern_info(full)
            info["ping"] = ping
            info["bytes"] = len(full)
            info["raw"] = full.hex(" ")
            return info

    # --------------------------------------------------------
    # Legacy GoldSrc details
    # --------------------------------------------------------

    legacy_packet = (
        b"\xff\xff\xff\xff"
        b"details\x00"
    )

    data, ping, addr = send_recv(sock, target, legacy_packet)

    if data:

        full = receive_response(sock, data, target)

        if full and full[:5] == b"\xff\xff\xff\xff\x6d":
            info = parse_legacy_info(full)
            info["ping"] = ping
            info["bytes"] = len(full)
            info["raw"] = full.hex(" ")
            return info

    return None


# ============================================================
# LEGACY GOLD-SRC PLAYERS
# ============================================================

def parse_legacy_players(data):

    players = []

    if len(data) < 6:
        return players

    if data[:5] != b"\xff\xff\xff\xff\x44":
        return players

    pos = 5

    count, pos = safe_u8(data, pos)

    for _ in range(count):

        if pos >= len(data):
            break

        index, pos = safe_u8(data, pos)

        name, pos = read_cstring(data, pos)

        score, pos = safe_i32(data, pos)

        duration, pos = safe_float(data, pos)

        players.append({
            "index": index,
            "name": name,
            "score": score,
            "duration": duration
        })

    return players


def query_legacy_players(sock, target):

    packet = (
        b"\xff\xff\xff\xff"
        b"players\x00"
    )

    data, ping, addr = send_recv(sock, target, packet)

    if not data:
        return [], None, None, "No response"

    full = receive_response(sock, data, target)

    if not full:
        return [], ping, None, "Empty response"

    if full[:5] != b"\xff\xff\xff\xff\x44":
        return [], ping, full, "Unexpected legacy players response"

    players = parse_legacy_players(full)

    return players, ping, full, None


# ============================================================
# MODERN A2S PLAYER
# ============================================================

def get_challenge(sock, target):

    packet = (
        b"\xff\xff\xff\xff"
        b"\x57"
    )

    data, ping, addr = send_recv(sock, target, packet)

    if not data:
        return None

    full = receive_response(sock, data, target)

    if not full:
        return None

    # A2S challenge response:
    #
    # FF FF FF FF 41 [4-byte challenge]

    if full[:5] == b"\xff\xff\xff\xff\x41" and len(full) >= 9:
        return full[5:9]

    return None


def query_modern_players(sock, target):

    challenge = get_challenge(sock, target)

    if challenge is None:
        # Some servers accept -1 directly
        challenge = b"\xff\xff\xff\xff"

    packet = (
        b"\xff\xff\xff\xff"
        b"\x55"
        + challenge
    )

    data, ping, addr = send_recv(sock, target, packet)

    if not data:
        return [], None, None, "No A2S_PLAYER response"

    full = receive_response(sock, data, target)

    if not full:
        return [], ping, None, "Empty response"

    # If server returned another challenge
    if full[:5] == b"\xff\xff\xff\xff\x41" and len(full) >= 9:

        challenge = full[5:9]

        packet = (
            b"\xff\xff\xff\xff"
            b"\x55"
            + challenge
        )

        data, ping, addr = send_recv(sock, target, packet)

        if not data:
            return [], ping, None, "No response after challenge"

        full = receive_response(sock, data, target)

    if full[:5] != b"\xff\xff\xff\xff\x44":
        return [], ping, full, "Unexpected A2S_PLAYER response"

    players = parse_legacy_players(full)

    return players, ping, full, None


# ============================================================
# LEGACY RULES
# ============================================================

def parse_rules(data):

    rules = []

    if len(data) < 7:
        return rules

    if data[:5] != b"\xff\xff\xff\xff\x45":
        return rules

    pos = 5

    count, pos = safe_u16(data, pos)

    for _ in range(count):

        key, pos = read_cstring(data, pos)

        value, pos = read_cstring(data, pos)

        rules.append({
            "key": key,
            "value": value
        })

    return rules


def query_legacy_rules(sock, target):

    packet = (
        b"\xff\xff\xff\xff"
        b"rules\x00"
    )

    data, ping, addr = send_recv(sock, target, packet)

    if not data:
        return [], None, None, "No response"

    full = receive_response(sock, data, target)

    if not full:
        return [], ping, None, "Empty response"

    if full[:5] != b"\xff\xff\xff\xff\x45":
        return [], ping, full, "Unexpected legacy rules response"

    rules = parse_rules(full)

    return rules, ping, full, None


# ============================================================
# MODERN A2S RULES
# ============================================================

def query_modern_rules(sock, target):

    challenge = get_challenge(sock, target)

    if challenge is None:
        challenge = b"\xff\xff\xff\xff"

    packet = (
        b"\xff\xff\xff\xff"
        b"\x56"
        + challenge
    )

    data, ping, addr = send_recv(sock, target, packet)

    if not data:
        return [], None, None, "No A2S_RULES response"

    full = receive_response(sock, data, target)

    if not full:
        return [], ping, None, "Empty response"

    # Challenge response
    if full[:5] == b"\xff\xff\xff\xff\x41" and len(full) >= 9:

        challenge = full[5:9]

        packet = (
            b"\xff\xff\xff\xff"
            b"\x56"
            + challenge
        )

        data, ping, addr = send_recv(sock, target, packet)

        if not data:
            return [], ping, None, "No response after challenge"

        full = receive_response(sock, data, target)

    if full[:5] != b"\xff\xff\xff\xff\x45":
        return [], ping, full, "Unexpected A2S_RULES response"

    rules = parse_rules(full)

    return rules, ping, full, None


# ============================================================
# FORMAT PLAY TIME
# ============================================================

def format_duration(seconds):

    try:
        seconds = float(seconds)
    except Exception:
        return "0s"

    if seconds < 0:
        seconds = 0

    total = int(seconds)

    hours = total // 3600
    minutes = (total % 3600) // 60
    secs = total % 60

    if hours > 0:
        return f"{hours}h {minutes}m {secs}s"

    if minutes > 0:
        return f"{minutes}m {secs}s"

    return f"{secs}s"


# ============================================================
# REVERSE DNS
# ============================================================

def reverse_dns(ip):

    try:
        host = socket.gethostbyaddr(ip)[0]

        if host == ip:
            return ""

        return host

    except Exception:
        return ""


# ============================================================
# HTML
# ============================================================

HTML = r"""
<!DOCTYPE html>
<html>
<head>

<meta charset="UTF-8">

<title>GoldSrc / WON Server Query</title>

<style>

body {
    font-family: Arial, sans-serif;
    background: #111;
    color: #eee;
    margin: 0;
    padding: 25px;
}

.container {
    max-width: 1100px;
    margin: auto;
}

h1 {
    margin-bottom: 5px;
}

.card {
    background: #1d1d1d;
    border: 1px solid #333;
    border-radius: 8px;
    padding: 18px;
    margin-top: 18px;
}

input {
    background: #111;
    color: white;
    border: 1px solid #555;
    padding: 10px;
    border-radius: 5px;
}

button {
    padding: 10px 18px;
    border: 0;
    border-radius: 5px;
    cursor: pointer;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th, td {
    text-align: left;
    padding: 8px;
    border-bottom: 1px solid #333;
}

th {
    background: #252525;
}

.good {
    color: #6cff6c;
}

.bad {
    color: #ff6666;
}

.raw {
    white-space: pre-wrap;
    word-break: break-all;
    font-family: monospace;
    font-size: 12px;
    color: #aaa;
}

.small {
    color: #aaa;
    font-size: 13px;
}

</style>

</head>

<body>

<div class="container">

<h1>GoldSrc / WON Server Query</h1>

<form method="get">

<input
    name="ip"
    value="{{ target_ip }}"
    placeholder="IP / hostname"
    required
>

<input
    name="port"
    value="{{ target_port }}"
    placeholder="Port"
    size="6"
    required
>

<button type="submit">
Query
</button>

</form>


{% if error %}

<div class="card">

<h2 class="bad">Offline / Error</h2>

<p>{{ error }}</p>

</div>

{% endif %}


{% if info %}

<div class="card">

<h2 class="good">
Server Online
</h2>

<table>

<tr>
<th>Target</th>
<td>{{ target_ip }}:{{ target_port }}</td>
</tr>

<tr>
<th>Hostname</th>
<td>{{ hostname }}</td>
</tr>

<tr>
<th>Ping</th>
<td>{{ "%.2f"|format(info.ping) }} ms</td>
</tr>

<tr>
<th>Bytes</th>
<td>{{ info.bytes }}</td>
</tr>

<tr>
<th>Response</th>
<td>{{ info.response_type }}</td>
</tr>

<tr>
<th>Server Name</th>
<td>{{ info.name }}</td>
</tr>

<tr>
<th>Map</th>
<td>{{ info.map }}</td>
</tr>

<tr>
<th>Game / Mod</th>
<td>{{ info.game }}</td>
</tr>

<tr>
<th>Folder</th>
<td>{{ info.folder }}</td>
</tr>

<tr>
<th>Protocol</th>
<td>{{ info.protocol }}</td>
</tr>

<tr>
<th>Players</th>
<td>
{{ info.players }}/{{ info.maxplayers }}
</td>
</tr>

<tr>
<th>Bots</th>
<td>{{ info.bots }}</td>
</tr>

<tr>
<th>Server Type</th>
<td>{{ info.type }}</td>
</tr>

<tr>
<th>OS</th>
<td>{{ info.os }}</td>
</tr>

<tr>
<th>Password</th>
<td>{{ info.password }}</td>
</tr>

<tr>
<th>VAC / Secure</th>
<td>{{ info.vac }}</td>
</tr>

<tr>
<th>Modded</th>
<td>{{ info.mod }}</td>
</tr>

</table>

</div>


<!-- PLAYERS -->

<div class="card">

<h2>
Players ({{ players|length }})
</h2>

{% if players %}

<table>

<tr>
<th>#</th>
<th>Name</th>
<th>Score</th>
<th>Play Time</th>
</tr>

{% for p in players %}

<tr>

<td>{{ p.index }}</td>

<td>{{ p.name }}</td>

<td>{{ p.score }}</td>

<td>{{ p.playtime }}</td>

</tr>

{% endfor %}

</table>

{% else %}

<p class="bad">
{{ players_error }}
</p>

{% endif %}

</div>


<!-- RULES -->

<div class="card">

<h2>
Server Rules ({{ rules|length }})
</h2>

{% if rules %}

<table>

<tr>
<th>Rule</th>
<th>Value</th>
</tr>

{% for r in rules %}

<tr>

<td>{{ r.key }}</td>

<td>{{ r.value }}</td>

</tr>

{% endfor %}

</table>

{% else %}

<p class="bad">
{{ rules_error }}
</p>

{% endif %}

</div>


<!-- RAW INFO -->

<div class="card">

<h2>
Raw Info Packet
</h2>

<div class="raw">
{{ info.raw }}
</div>

</div>


{% if players_raw %}

<div class="card">

<h2>
Raw Players Packet
</h2>

<div class="raw">
{{ players_raw }}
</div>

</div>

{% endif %}


{% if rules_raw %}

<div class="card">

<h2>
Raw Rules Packet
</h2>

<div class="raw">
{{ rules_raw }}
</div>

</div>

{% endif %}


{% endif %}

</div>

</body>
</html>
"""


# ============================================================
# MAIN QUERY
# ============================================================

@app.route("/")
def index():

    target_ip = request.args.get("ip", "")
    target_port = request.args.get("port", "27015")

    info = None
    hostname = ""
    error = None

    players = []
    rules = []

    players_error = "Not queried"
    rules_error = "Not queried"

    players_raw = None
    rules_raw = None

    if target_ip:

        try:
            port = int(target_port)

            if port < 1 or port > 65535:
                raise ValueError("Invalid port")

        except Exception:
            return render_template_string(
                HTML,
                target_ip=target_ip,
                target_port=target_port,
                info=None,
                hostname="",
                error="Invalid port",
                players=[],
                rules=[],
                players_error="Not queried",
                rules_error="Not queried",
                players_raw=None,
                rules_raw=None
            )

        try:

            target = (target_ip, port)

            # Resolve hostname
            try:
                socket.inet_aton(target_ip)
                hostname = reverse_dns(target_ip)
            except Exception:
                hostname = ""

            sock = make_socket()

            # ------------------------------------------------
            # INFO
            # ------------------------------------------------

            info = query_info(sock, target)

            if not info:

                sock.close()

                return render_template_string(
                    HTML,
                    target_ip=target_ip,
                    target_port=target_port,
                    info=None,
                    hostname=hostname,
                    error="No response from server",
                    players=[],
                    rules=[],
                    players_error="Not queried",
                    rules_error="Not queried",
                    players_raw=None,
                    rules_raw=None
                )

            # ------------------------------------------------
            # IMPORTANT:
            #
            # 0x6D = old GoldSrc/WON style
            # 0x49 = modern A2S
            # ------------------------------------------------

            if info["response_type"] == "0x6D":

                # Legacy GoldSrc
                players, _, raw, err = query_legacy_players(
                    sock,
                    target
                )

                players_raw = raw.hex(" ") if raw else None

                if err:
                    players_error = err
                else:
                    players_error = "No players"

                rules, _, raw, err = query_legacy_rules(
                    sock,
                    target
                )

                rules_raw = raw.hex(" ") if raw else None

                if err:
                    rules_error = err
                else:
                    rules_error = "No rules"

            else:

                # Modern A2S
                players, _, raw, err = query_modern_players(
                    sock,
                    target
                )

                players_raw = raw.hex(" ") if raw else None

                if err:
                    players_error = err
                else:
                    players_error = "No players"

                rules, _, raw, err = query_modern_rules(
                    sock,
                    target
                )

                rules_raw = raw.hex(" ") if raw else None

                if err:
                    rules_error = err
                else:
                    rules_error = "No rules"

            sock.close()

            # Format duration
            for p in players:
                p["playtime"] = format_duration(
                    p["duration"]
                )

        except Exception as e:

            error = str(e)

    return render_template_string(
        HTML,

        target_ip=target_ip,
        target_port=target_port,

        info=info,
        hostname=hostname,

        error=error,

        players=players,
        rules=rules,

        players_error=players_error,
        rules_error=rules_error,

        players_raw=players_raw,
        rules_raw=rules_raw
    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health")
def health():

    return "OK"


# ============================================================
# LOCAL RUN
# ============================================================

if __name__ == "__main__":

    import os

    port = int(
        os.environ.get(
            "PORT",
            "10000"
        )
    )

    app.run(
        host="0.0.0.0",
        port=port
    )
