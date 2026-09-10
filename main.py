import os
import socket
import struct
import time
from flask import Flask, request, render_template_string

app = Flask(__name__)


HTML = r"""
<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>WON2 / GoldSrc Server Checker</title>

    <style>
        body {
            background: #111;
            color: #eee;
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
        }

        .box {
            max-width: 700px;
            margin: auto;
            background: #1d1d1d;
            padding: 20px;
            border-radius: 12px;
        }

        h1 {
            font-size: 24px;
        }

        input {
            width: 100%;
            box-sizing: border-box;
            padding: 12px;
            margin: 6px 0 12px;
            background: #292929;
            border: 1px solid #555;
            color: white;
            border-radius: 6px;
        }

        button {
            width: 100%;
            padding: 13px;
            background: #444;
            color: white;
            border: 0;
            border-radius: 6px;
            font-size: 16px;
        }

        button:hover {
            background: #666;
        }

        .result {
            margin-top: 20px;
            background: #101010;
            padding: 15px;
            border-radius: 8px;
        }

        .ok {
            color: #5cff75;
        }

        .bad {
            color: #ff5555;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        td {
            padding: 7px;
            border-bottom: 1px solid #333;
        }

        td:first-child {
            font-weight: bold;
            width: 40%;
        }

        pre {
            white-space: pre-wrap;
            word-break: break-all;
            font-size: 11px;
            color: #aaa;
        }

        .small {
            color: #999;
            font-size: 13px;
        }
    </style>
</head>

<body>

<div class="box">

<h1>WON2 / GoldSrc Server Checker</h1>

<form method="POST">

    <label>IP address / hostname</label>

    <input
        name="ip"
        value="{{ ip }}"
        placeholder="185.107.96.202"
        required
    >

    <label>Port</label>

    <input
        name="port"
        value="{{ port }}"
        placeholder="27015"
        type="number"
        min="1"
        max="65535"
        required
    >

    <button type="submit">CHECK SERVER</button>

</form>

{% if result %}

<div class="result">

    {% if result.error %}

        <h2 class="bad">✗ {{ result.error }}</h2>

    {% else %}

        {% if result.response %}

            <h2 class="ok">✓ SERVER ANSWERED</h2>

        {% else %}

            <h2 class="bad">✗ NO UDP RESPONSE</h2>

        {% endif %}

        <table>

            <tr>
                <td>Target</td>
                <td>{{ result.target }}</td>
            </tr>

            <tr>
                <td>Hostname</td>
                <td>{{ result.hostname }}</td>
            </tr>

            <tr>
                <td>Ping</td>
                <td>{{ result.ping }}</td>
            </tr>

            <tr>
                <td>Bytes received</td>
                <td>{{ result.bytes }}</td>
            </tr>

            <tr>
                <td>Response type</td>
                <td>{{ result.response_type }}</td>
            </tr>

            {% if result.name %}
            <tr>
                <td>Server name</td>
                <td>{{ result.name }}</td>
            </tr>
            {% endif %}

            {% if result.map %}
            <tr>
                <td>Map</td>
                <td>{{ result.map }}</td>
            </tr>
            {% endif %}

            {% if result.folder %}
            <tr>
                <td>Folder</td>
                <td>{{ result.folder }}</td>
            </tr>
            {% endif %}

            {% if result.game %}
            <tr>
                <td>Game</td>
                <td>{{ result.game }}</td>
            </tr>
            {% endif %}

            {% if result.protocol %}
            <tr>
                <td>Protocol</td>
                <td>{{ result.protocol }}</td>
            </tr>
            {% endif %}

            {% if result.players is not none %}
            <tr>
                <td>Players</td>
                <td>{{ result.players }} / {{ result.max_players }}</td>
            </tr>
            {% endif %}

            {% if result.bots is not none %}
            <tr>
                <td>Bots</td>
                <td>{{ result.bots }}</td>
            </tr>
            {% endif %}

            {% if result.server_type %}
            <tr>
                <td>Server type</td>
                <td>{{ result.server_type }}</td>
            </tr>
            {% endif %}

            {% if result.os %}
            <tr>
                <td>OS</td>
                <td>{{ result.os }}</td>
            </tr>
            {% endif %}

            {% if result.password is not none %}
            <tr>
                <td>Password</td>
                <td>{{ result.password }}</td>
            </tr>
            {% endif %}

            {% if result.vac is not none %}
            <tr>
                <td>VAC</td>
                <td>{{ result.vac }}</td>
            </tr>
            {% endif %}

        </table>

        {% if result.message %}
            <p>{{ result.message }}</p>
        {% endif %}

        <h3>Raw packet</h3>

        <pre>{{ result.hex }}</pre>

    {% endif %}

</div>

{% endif %}

<p class="small">
    Queries are sent using UDP A2S/legacy GoldSrc protocol.
</p>

</div>

</body>
</html>
"""


def read_cstring(data, pos):
    end = data.find(b"\x00", pos)

    if end == -1:
        raise ValueError("Missing string terminator")

    value = data[pos:end].decode("utf-8", errors="replace")

    return value, end + 1


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "No reverse DNS"


def query_server(ip, port):

    result = {
        "target": "%s:%d" % (ip, port),
        "hostname": reverse_dns(ip),
        "response": False,
        "ping": "-",
        "bytes": 0,
        "response_type": "-",
        "name": None,
        "map": None,
        "folder": None,
        "game": None,
        "protocol": None,
        "players": None,
        "max_players": None,
        "bots": None,
        "server_type": None,
        "os": None,
        "password": None,
        "vac": None,
        "message": "",
        "hex": ""
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    # A2S_INFO
    packet = (
        b"\xff\xff\xff\xff"
        b"\x54"
        b"Source Engine Query\x00"
    )

    try:

        start = time.time()

        sock.sendto(packet, (ip, port))

        data, address = sock.recvfrom(65535)

        elapsed = (time.time() - start) * 1000

        result["response"] = True
        result["ping"] = "%.1f ms" % elapsed
        result["bytes"] = len(data)
        result["hex"] = data.hex(" ")

        if len(data) < 5:
            result["message"] = "Response was too short."
            return result

        response_type = data[4]

        result["response_type"] = "0x%02X" % response_type

        # ==================================================
        # LEGACY GOLDSRC
        # ==================================================

        if response_type == 0x6D:

            result["message"] = "Legacy GoldSrc response detected."

            pos = 5

            try:

                address_text, pos = read_cstring(data, pos)
                name, pos = read_cstring(data, pos)
                map_name, pos = read_cstring(data, pos)
                folder, pos = read_cstring(data, pos)
                game, pos = read_cstring(data, pos)

                result["name"] = name
                result["map"] = map_name
                result["folder"] = folder
                result["game"] = game

                if pos + 7 <= len(data):

                    result["players"] = data[pos]
                    result["max_players"] = data[pos + 1]
                    result["protocol"] = data[pos + 2]

                    result["server_type"] = chr(data[pos + 3])
                    result["os"] = chr(data[pos + 4])

                    result["password"] = bool(data[pos + 5])

                return result

            except Exception as e:

                result["message"] = (
                    "Legacy response detected but parsing failed: "
                    + repr(e)
                )

                return result

        # ==================================================
        # NORMAL A2S INFO
        # ==================================================

        if response_type == 0x49:

            result["message"] = "Standard A2S_INFO response detected."

            pos = 5

            try:

                result["protocol"] = data[pos]
                pos += 1

                result["name"], pos = read_cstring(data, pos)
                result["map"], pos = read_cstring(data, pos)
                result["folder"], pos = read_cstring(data, pos)
                result["game"], pos = read_cstring(data, pos)

                # App ID
                if pos + 2 <= len(data):

                    pos += 2

                if pos < len(data):

                    result["players"] = data[pos]
                    pos += 1

                if pos < len(data):

                    result["max_players"] = data[pos]
                    pos += 1

                # Number of bots
                if pos < len(data):

                    result["bots"] = data[pos]
                    pos += 1

                # Server type
                if pos < len(data):

                    result["server_type"] = chr(data[pos])
                    pos += 1

                # OS
                if pos < len(data):

                    result["os"] = chr(data[pos])
                    pos += 1

                # Password
                if pos < len(data):

                    result["password"] = bool(data[pos])
                    pos += 1

                # VAC
                #
                # This location can vary depending on whether
                # the server reports an EDF field.
                #
                if pos < len(data):

                    # skip EDF if present in a safe way
                    result["vac"] = None

                return result

            except Exception as e:

                result["message"] = (
                    "A2S response detected but parsing failed: "
                    + repr(e)
                )

                return result

        # ==================================================
        # UNKNOWN
        # ==================================================

        result["message"] = (
            "Server answered, but the response is not a normal "
            "A2S_INFO or legacy 0x6D response."
        )

        return result

    except socket.timeout:

        result["message"] = (
            "No UDP response after 5 seconds. "
            "The port may be closed, filtered, wrong, "
            "or the server may use another protocol."
        )

        return result

    except Exception as e:

        result["error"] = repr(e)

        return result

    finally:

        sock.close()


@app.route("/", methods=["GET", "POST"])
def index():

    ip = ""
    port = "27015"
    result = None

    if request.method == "POST":

        ip = request.form.get("ip", "").strip()
        port_text = request.form.get("port", "").strip()

        try:
            port = int(port_text)
        except:
            result = {
                "error": "Invalid port."
            }

            return render_template_string(
                HTML,
                ip=ip,
                port=port,
                result=result
            )

        # Basic validation

        if not ip:

            result = {
                "error": "Enter an IP address or hostname."
            }

            return render_template_string(
                HTML,
                ip=ip,
                port=port,
                result=result
            )

        if port < 1 or port > 65535:

            result = {
                "error": "Port must be between 1 and 65535."
            }

            return render_template_string(
                HTML,
                ip=ip,
                port=port,
                result=result
            )

        # Resolve hostname/IP

        try:

            resolved_ip = socket.gethostbyname(ip)

        except Exception:

            result = {
                "error": "Could not resolve that IP/hostname."
            }

            return render_template_string(
                HTML,
                ip=ip,
                port=port,
                result=result
            )

        result = query_server(resolved_ip, port)

    return render_template_string(
        HTML,
        ip=ip,
        port=port,
        result=result
    )


@app.route("/health")
def health():

    return "OK", 200


if __name__ == "__main__":

    port = int(os.environ.get("PORT", "10000"))

    app.run(
        host="0.0.0.0",
        port=port
                )
