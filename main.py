import socket
import struct

# =========================
# PUT YOUR SERVER HERE
# =========================
SERVER_IP = "185.107.96.202"
SERVER_PORT = 27015

TIMEOUT = 3


def read_string(data, pos):
    end = data.find(b"\x00", pos)

    if end == -1:
        raise ValueError("Invalid packet: missing string terminator")

    return data[pos:end].decode("utf-8", errors="replace"), end + 1


def query_server():
    # A2S_INFO
    packet = (
        b"\xff\xff\xff\xff"
        b"\x54"
        b"Source Engine Query\x00"
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    try:
        print("Querying %s:%d..." % (SERVER_IP, SERVER_PORT))

        sock.sendto(packet, (SERVER_IP, SERVER_PORT))

        data, address = sock.recvfrom(8192)

        print("Received %d bytes from %s:%d"
              % (len(data), address[0], address[1]))

        # Split packet handling
        if data[:4] == b"\xfe\xff\xff\xff":
            print("Server returned a split packet.")
            print("Raw packet:")
            print(data.hex(" "))
            return

        if len(data) < 6:
            print("Response is too short.")
            return

        header = data[:4]
        response_type = data[4]

        print("Header:", header.hex(" "))
        print("Response type: 0x%02X" % response_type)

        # Normal A2S_INFO response
        if response_type != 0x49:
            print("Unknown/old response type.")
            print("Raw:")
            print(data.hex(" "))
            return

        pos = 5

        protocol = data[pos]
        pos += 1

        name, pos = read_string(data, pos)
        map_name, pos = read_string(data, pos)
        folder, pos = read_string(data, pos)
        game, pos = read_string(data, pos)

        player_count = data[pos]
        pos += 1

        max_players = data[pos]
        pos += 1

        bot_count = data[pos]
        pos += 1

        server_type = chr(data[pos])
        pos += 1

        platform = chr(data[pos])
        pos += 1

        password = data[pos] != 0
        pos += 1

        vac = data[pos] != 0
        pos += 1

        version, pos = read_string(data, pos)

        print()
        print("========== SERVER STATUS ==========")
        print("Address :", "%s:%d" % (SERVER_IP, SERVER_PORT))
        print("Name    :", name)
        print("Map     :", map_name)
        print("Folder  :", folder)
        print("Game    :", game)
        print("Protocol:", protocol)
        print("Players :", "%d/%d" % (player_count, max_players))
        print("Bots    :", bot_count)
        print("Type    :", server_type)
        print("OS      :", platform)
        print("Password:", password)
        print("VAC     :", vac)
        print("Version :", version)
        print("===================================")

    except socket.timeout:
        print("TIMEOUT: Server did not answer.")

    except Exception as e:
        print("ERROR:", e)

    finally:
        sock.close()


if __name__ == "__main__":
    query_server()
