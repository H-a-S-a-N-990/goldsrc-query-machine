from flask import Flask, request, render_template_string
import socket
import struct
import time
import os

app = Flask(__name__)

TIMEOUT = 5.0


# ============================================================
# SOCKET / PACKET
# ============================================================

def make_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    return s


def send_packet(sock, target, packet):
    start = time.time()

    sock.sendto(packet, target)

    data, addr = sock.recvfrom(65535)

    ping = (time.time() - start) * 1000.0

    return data, ping


# ============================================================
# BASIC READERS
# ============================================================

def read_cstring(data, pos):
    if pos >= len(data):
        return "", len(data)

    end = data.find(b"\x00", pos)

    if end == -1:
        return data[pos:].decode("utf-8", "replace"), len(data)

    return data[pos:end].decode("utf-8", "replace"), end + 1


def read_u8(data, pos):
    if pos + 1 > len(data):
        raise ValueError("Packet ended while reading u8")

    return data[pos], pos + 1


def read_u16(data, pos):
    if pos + 2 > len(data):
        raise ValueError("Packet ended while reading u16")

    return struct.unpack_from("<H", data, pos)[0], pos + 2


def read_u32(data, pos):
    if pos + 4 > len(data):
        raise ValueError("Packet ended while reading u32")

    return struct.unpack_from("<I", data, pos)[0], pos + 4


def read_i32(data, pos):
    if pos + 4 > len(data):
        raise ValueError("Packet ended while reading i32")

    return struct.unpack_from("<i", data, pos)[0], pos + 4


def read_float(data, pos):
    if pos + 4 > len(data):
        raise ValueError("Packet ended while reading float")

    return struct.unpack_from("<f", data, pos)[0], pos + 4


# ============================================================
# GOLDsrc SPLIT PACKETS
#
# GoldSrc split header:
#
# FF FF FF FE
# 4 byte packet ID
# 1 byte:
#     upper bits = fragment index
#     lower 4 bits = total fragments
#
# The payload begins at byte 9.
# ============================================================

def is_split(data):
    return len(data) >= 4 and data[:4] == b"\xff\xff\xff\xfe"


def split_header(data):
    if len(data) < 9:
        return None

    packet_id = data[4:8]
    info = data[8]

    index = info >> 4
    total = info & 0x0F

    return packet_id, index, total


def receive_complete(sock, first):

    # Normal GoldSrc/A2S packet
    if not is_split(first):
        return first

    h = split_header(first)

    if h is None:
        return first

    packet_id, index, total = h

    if total <= 1:
        return first[9:]

    pieces = {}

    pieces[index] = first[9:]

    deadline = time.time() + TIMEOUT

    while len(pieces) < total:

        remaining = deadline - time.time()

        if remaining <= 0:
            raise socket.timeout(
                "Timed out waiting for GoldSrc split packets"
            )

        sock.settimeout(remaining)

        packet, addr = sock.recvfrom(65535)

        if not is_split(packet):
            continue

        h2 = split_header(packet)

        if h2 is None:
            continue

        packet_id2, index2, total2 = h2

        if packet_id2 != packet_id:
            continue

        if total2 != total:
            continue

        pieces[index2] = packet[9:]

    result = b""

    for i in range(total):
        if i not in pieces:
            raise ValueError(
                "Missing split packet %d/%d" %
                (i, total)
            )

        result += pieces[i]

    return result


# ============================================================
# INFO
# ============================================================

def parse_legacy_info(data):

    if len(data) < 6:
        raise ValueError("Legacy info packet too short")

    if data[:5] != b"\xff\xff\xff\xff\x6d":
        raise ValueError("Not a GoldSrc 0x6D response")

    pos = 5

    result = {}

    result["address"], pos = read_cstring(data, pos)
    result["name"], pos = read_cstring(data, pos)
    result["map"], pos = read_cstring(data, pos)
    result["folder"], pos = read_cstring(data, pos)
    result["game"], pos = read_cstring(data, pos)

    result["players"], pos = read_u8(data, pos)
    result["maxplayers"], pos = read_u8(data, pos)
    result["protocol"], pos = read_u8(data, pos)

    result["type"] = chr(data[pos])
    pos += 1

    result["os"] = chr(data[pos])
    pos += 1

    password, pos = read_u8(data, pos)
    result["password"] = bool(password)

    mod, pos = read_u8(data, pos)
    result["mod"] = bool(mod)

    if mod:

        result["mod_website"], pos = read_cstring(data, pos)
        result["mod_download"], pos = read_cstring(data, pos)

        if pos < len(data):
            pos += 1

        result["mod_version"], pos = read_u32(data, pos)
        result["mod_size"], pos = read_u32(data, pos)

        result["mod_type"], pos = read_u8(data, pos)
        result["mod_dll"], pos = read_u8(data, pos)

    # Secure / VAC
    if pos < len(data):
        secure, pos = read_u8(data, pos)
        result["vac"] = bool(secure)
    else:
        result["vac"] = False

    # Bots
    if pos < len(data):
        result["bots"], pos = read_u8(data, pos)
    else:
        result["bots"] = 0

    return result


def parse_modern_info(data):

    if len(data) < 6:
        raise ValueError("Modern info packet too short")

    if data[:5] != b"\xff\xff\xff\xff\x49":
        raise ValueError("Not a 0x49 response")

    pos = 5

    result = {}

    result["protocol"], pos = read_u8(data, pos)

    result["name"], pos = read_cstring(data, pos)
    result["map"], pos = read_cstring(data, pos)
    result["folder"], pos = read_cstring(data, pos)
    result["game"], pos = read_cstring(data, pos)

    result["appid"], pos = read_u16(data, pos)

    result["players"], pos = read_u8(data, pos)
    result["maxplayers"], pos = read_u8(data, pos)
    result["bots"], pos = read_u8(data, pos)

    result["type"] = chr(data[pos])
    pos += 1

    result["os"] = chr(data[pos])
    pos += 1

    password, pos = read_u8(data, pos)
    result["password"] = bool(password)

    vac, pos = read_u8(data, pos)
    result["vac"] = bool(vac)

    result["version"], pos = read_cstring(data, pos)

    return result


def query_info(sock, target):

    # --------------------------------------------------------
    # First: modern A2S_INFO
    # --------------------------------------------------------

    packet = (
        b"\xff\xff\xff\xff"
        b"\x54"
        b"Source Engine Query\x00"
    )

    try:

        data, ping = send_packet(
            sock,
            target,
            packet
        )

        data = receive_complete(
            sock,
            data
        )

        if data[:5] == b"\xff\xff\xff\xff\x49":

            info = parse_modern_info(data)

            info["response_type"] = "0x49"
            info["ping"] = ping
            info["bytes"] = len(data)
            info["raw"] = data.hex(" ")

            return info

    except Exception:
        pass

    # --------------------------------------------------------
    # Legacy GoldSrc details
    # --------------------------------------------------------

    packet = (
        b"\xff\xff\xff\xff"
        b"details\x00"
    )

    data, ping = send_packet(
        sock,
        target,
        packet
    )

    data = receive_complete(
        sock,
        data
    )

    if data[:5] != b"\xff\xff\xff\xff\x6d":
        raise ValueError(
            "Server did not return GoldSrc details"
        )

    info = parse_legacy_info(data)

    info["response_type"] = "0x6D"
    info["ping"] = ping
    info["bytes"] = len(data)
    info["raw"] = data.hex(" ")

    return info


# ============================================================
# PLAYER RESPONSE
# ============================================================

def parse_players(data):

    if len(data) < 6:
        raise ValueError("Player response too short")

    if data[:5] != b"\xff\xff\xff\xff\x44":
        raise ValueError(
            "Unexpected player response: " +
            data[:16].hex(" ")
        )

    pos = 5

    count, pos = read_u8(data, pos)

    players = []

    for _ in range(count):

        index, pos = read_u8(data, pos)

        name, pos = read_cstring(
            data,
            pos
        )

        score, pos = read_i32(
            data,
            pos
        )

        duration, pos = read_float(
            data,
            pos
        )

        players.append({
            "index": index,
            "name": name,
            "score": score,
            "duration": duration
        })

    return players


# ============================================================
# RULE RESPONSE
# ============================================================

def parse_rules(data):

    if len(data) < 7:
        raise ValueError("Rules response too short")

    if data[:5] != b"\xff\xff\xff\xff\x45":
        raise ValueError(
            "Unexpected rules response: " +
            data[:16].hex(" ")
        )

    pos = 5

    count, pos = read_u16(
        data,
        pos
    )

    rules = {}

    for _ in range(count):

        key, pos = read_cstring(
            data,
            pos
        )

        value, pos = read_cstring(
            data,
            pos
        )

        rules[key] = value

    return rules


# ============================================================
# CHALLENGE
# ============================================================

def get_challenge(sock, target):

    # A2S challenge
    packet = (
        b"\xff\xff\xff\xff"
        b"\x57"
    )

    try:

        data, ping = send_packet(
            sock,
            target,
            packet
        )

        data = receive_complete(
            sock,
            data
        )

        if (
            data[:5] ==
            b"\xff\xff\xff\xff\x41"
            and len(data) >= 9
        ):
            return data[5:9]

    except Exception:
        pass

    return None


# ============================================================
# MODERN PLAYER QUERY
# ============================================================

def query_modern_players(sock, target):

    challenge = get_challenge(
        sock,
        target
    )

    if challenge is None:
        challenge = b"\xff\xff\xff\xff"

    packet = (
        b"\xff\xff\xff\xff"
        b"\x55"
        + challenge
    )

    data, ping = send_packet(
        sock,
        target,
        packet
    )

    data = receive_complete(
        sock,
        data
    )

    # Server gave us a challenge instead
    if (
        data[:5] ==
        b"\xff\xff\xff\xff\x41"
        and len(data) >= 9
    ):

        challenge = data[5:9]

        packet = (
            b"\xff\xff\xff\xff"
            b"\x55"
            + challenge
        )

        data, ping = send_packet(
            sock,
            target,
            packet
        )

        data = receive_complete(
            sock,
            data
        )

    return parse_players(data), data


# ============================================================
# MODERN RULES QUERY
# ============================================================

def query_modern_rules(sock, target):

    challenge = get_challenge(
        sock,
        target
    )

    if challenge is None:
        challenge = b"\xff\xff\xff\xff"

    packet = (
        b"\xff\xff\xff\xff"
        b"\x56"
        + challenge
    )

    data, ping = send_packet(
        sock,
        target,
        packet
    )

    data = receive_complete(
        sock,
        data
    )

    # Challenge response
    if (
        data[:5] ==
        b"\xff\xff\xff\xff\x41"
        and len(data) >= 9
    ):

        challenge = data[5:9]

        packet = (
            b"\xff\xff\xff\xff"
            b"\x56"
            + challenge
        )

        data, ping = send_packet(
            sock,
            target,
            packet
        )

        data = receive_complete(
            sock,
            data
        )

    return parse_rules(data), data


# ============================================================
# LEGACY PLAYERS
# ============================================================

def query_legacy_players(sock, target):

    packet = (
        b"\xff\xff\xff\xff"
        b"players\x00"
    )

    data, ping = send_packet(
        sock,
        target,
        packet
    )

    data = receive_complete(
        sock,
        data
    )

    return parse_players(data), data


# ============================================================
# LEGACY RULES
# ============================================================

def query_legacy_rules(sock, target):

    packet = (
        b"\xff\xff\xff\xff"
        b"rules\x00"
    )

    data, ping = send_packet(
        sock,
        target,
        packet
    )

    data = receive_complete(
        sock,
        data
    )

    return parse_rules(data), data


# ============================================================
# DURATION
# ============================================================

def format_duration(seconds):

    try:
        seconds = float(seconds)
    except Exception:
        return "0s"

    seconds = max(0, int(seconds))

    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60

    if hours:
        return f"{hours}h {minutes}m {secs}s"

    if minutes:
        return f"{minutes}m {secs}s"

    return f"{secs}s"


# ============================================================
# COMPLETE QUERY
# ============================================================

def query_server(ip, port):

    target = (
        ip,
        int(port)
    )

    result = {
        "online": False,
        "info": None,

        "players": [],
        "rules": {},

        "players_error": "",
        "rules_error": "",

        "players_raw": "",
        "rules_raw": ""
    }

    # --------------------------------------------------------
    # INFO
    # --------------------------------------------------------

    info_sock = make_socket()

    try:

        info = query_info(
            info_sock,
            target
        )

        result["online"] = True
        result["info"] = info

    except Exception as e:

        result["info_error"] = str(e)

        info_sock.close()

        return result

    info_sock.close()

    # --------------------------------------------------------
    # PLAYER QUERY
    #
    # Use separate socket.
    # This is important because challenge state belongs
    # to the query conversation.
    # --------------------------------------------------------

    player_sock = make_socket()

    try:

        if info["response_type"] == "0x6D":

            try:

                players, raw = query_modern_players(
                    player_sock,
                    target
                )

            except Exception:

                # Fallback to original GoldSrc query
                players, raw = query_legacy_players(
                    player_sock,
                    target
                )

        else:

            players, raw = query_modern_players(
                player_sock,
                target
            )

        result["players"] = players

        result["players_raw"] = raw.hex(" ")

        for p in result["players"]:
            p["playtime"] = format_duration(
                p["duration"]
            )

    except Exception as e:

        result["players_error"] = str(e)

    player_sock.close()

    # --------------------------------------------------------
    # RULES
    # --------------------------------------------------------

    rules_sock = make_socket()

    try:

        if info["response_type"] == "0x6D":

            try:

                rules, raw = query_modern_rules(
                    rules_sock,
                    target
                )

            except Exception:

                # Fallback to old GoldSrc query
                rules, raw = query_legacy_rules(
                    rules_sock,
                    target
                )

        else:

            rules, raw = query_modern_rules(
                rules_sock,
                target
            )

        result["rules"] = rules

        result["rules_raw"] = raw.hex(" ")

    except Exception as e:

        result["rules_error"] = str(e)

    rules_sock.close()

    return result


# ============================================================
# HTML
# ============================================================

HTML = """
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1">

<title>GoldSrc Server Query</title>

<style>

body {
    background:#111;
    color:#eee;
    font-family:Arial,sans-serif;
    margin:0;
    padding:20px;
}

.container {
    max-width:1100px;
    margin:auto;
}

.card {
    background:#1c1c1c;
    border:1px solid #333;
    border-radius:8px;
    padding:18px;
    margin-top:18px;
}

input {
    background:#111;
    color:white;
    border:1px solid #555;
    padding:10px;
    border-radius:5px;
}

button {
    padding:10px 18px;
    border:0;
    border-radius:5px;
    cursor:pointer;
}

table {
    width:100%;
    border-collapse:collapse;
}

th,td {
    padding:8px;
    border-bottom:1px solid #333;
    text-align:left;
}

th {
    background:#252525;
}

.online {
    color:#55ff55;
}

.error {
    color:#ff6666;
}

.warning {
    color:#ffcc55;
}

.mono {
    font-family:monospace;
}

.rule-key {
    font-family:monospace;
    width:45%;
}

.rule-value {
    font-family:monospace;
    word-break:break-word;
}

.raw {
    font-family:monospace;
    font-size:12px;
    color:#aaa;
    word-break:break-all;
}

</style>

</head>

<body>

<div class="container">

<h1>GoldSrc Server Query</h1>

<form>

<input
name="ip"
value="{{ ip }}"
placeholder="IP / hostname"
required
>

<input
name="port"
value="{{ port }}"
size="6"
placeholder="Port"
required
>

<button>
Query
</button>

</form>


{% if queried %}

{% if server.online %}

<div class="card">

<h2 class="online">
● Online
</h2>

<table>

<tr>
<th>Server Name</th>
<td>{{ server.info.name }}</td>
</tr>

<tr>
<th>Game</th>
<td>{{ server.info.game }}</td>
</tr>

<tr>
<th>State</th>
<td class="online">Online</td>
</tr>

<tr>
<th>Address</th>
<td class="mono">{{ server.info.address }}</td>
</tr>

<tr>
<th>Map</th>
<td>{{ server.info.map }}</td>
</tr>

<tr>
<th>Folder</th>
<td>{{ server.info.folder }}</td>
</tr>

<tr>
<th>Protocol</th>
<td>{{ server.info.protocol }}</td>
</tr>

<tr>
<th>Players</th>
<td>
{{ server.info.players }}/{{ server.info.maxplayers }}
</td>
</tr>

<tr>
<th>Bots</th>
<td>{{ server.info.bots }}</td>
</tr>

<tr>
<th>Server Type</th>
<td>{{ server.info.type }}</td>
</tr>

<tr>
<th>OS</th>
<td>{{ server.info.os }}</td>
</tr>

<tr>
<th>Password</th>
<td>{{ server.info.password }}</td>
</tr>

<tr>
<th>VAC / Secure</th>
<td>{{ server.info.vac }}</td>
</tr>

<tr>
<th>Query Ping</th>
<td>{{ "%.2f"|format(server.info.ping) }} ms</td>
</tr>

</table>

</div>


<div class="card">

<h2>
PLAYERS
</h2>

{% if server.players %}

<table>

<tr>
<th>#</th>
<th>Name</th>
<th>Score</th>
<th>Time</th>
</tr>

{% for p in server.players %}

<tr>

<td>{{ p.index }}</td>

<td>{{ p.name }}</td>

<td>{{ p.score }}</td>

<td>{{ p.playtime }}</td>

</tr>

{% endfor %}

</table>

{% else %}

<p class="warning">
No player records returned.
</p>

{% if server.players_error %}
<p class="error">
{{ server.players_error }}
</p>
{% endif %}

{% endif %}

</div>


<div class="card">

<h2>
SERVER VARIABLES
</h2>

{% if server.rules %}

<table>

<tr>
<th>Variable</th>
<th>Value</th>
</tr>

{% for key,value in server.rules.items() %}

<tr>

<td class="rule-key">
{{ key }}
</td>

<td class="rule-value">
{{ value }}
</td>

</tr>

{% endfor %}

</table>

<p>
{{ server.rules|length }} variables
</p>

{% else %}

<p class="warning">
No server variables returned.
</p>

{% if server.rules_error %}
<p class="error">
{{ server.rules_error }}
</p>
{% endif %}

{% endif %}

</div>


<div class="card">

<h2>
Raw Info
</h2>

<div class="raw">
{{ server.info.raw }}
</div>

</div>


{% if server.players_raw %}

<div class="card">

<h2>
Raw Players
</h2>

<div class="raw">
{{ server.players_raw }}
</div>

</div>

{% endif %}


{% if server.rules_raw %}

<div class="card">

<h2>
Raw Rules
</h2>

<div class="raw">
{{ server.rules_raw }}
</div>

</div>

{% endif %}


{% else %}

<div class="card">

<h2 class="error">
● Offline
</h2>

<p>
{{ server.info_error }}
</p>

</div>

{% endif %}

{% endif %}

</div>

</body>

</html>
"""


# ============================================================
# FLASK
# ============================================================

@app.route("/")
def index():

    ip = request.args.get(
        "ip",
        ""
    ).strip()

    port = request.args.get(
        "port",
        "27015"
    ).strip()

    queried = bool(ip)

    server = {
        "online": False,
        "info_error": ""
    }

    if queried:

        try:

            int_port = int(port)

            if not 1 <= int_port <= 65535:
                raise ValueError(
                    "Invalid port"
                )

            server = query_server(
                ip,
                int_port
            )

        except Exception as e:

            server = {
                "online": False,
                "info_error": str(e)
            }

    return render_template_string(
        HTML,
        ip=ip,
        port=port,
        queried=queried,
        server=server
    )


@app.route("/health")
def health():
    return "OK"


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

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
