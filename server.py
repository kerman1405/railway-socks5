import asyncio
import os
import struct


USERNAME = os.environ.get("USERNAME")
PASSWORD = os.environ.get("PASSWORD")
PORT = int(os.environ.get("PORT", "1080"))

if not USERNAME or not PASSWORD:
    raise RuntimeError("USERNAME and PASSWORD environment variables are required")


async def read_exact(reader, size):
    data = await reader.readexactly(size)
    return data


async def authenticate(reader, writer):
    version = (await read_exact(reader, 1))[0]

    if version != 0x05:
        return False

    nmethods = (await read_exact(reader, 1))[0]
    methods = await read_exact(reader, nmethods)

    # Username/Password authentication
    if 0x02 not in methods:
        writer.write(b"\x05\xff")
        await writer.drain()
        return False

    writer.write(b"\x05\x02")
    await writer.drain()

    # RFC 1929
    auth_version = (await read_exact(reader, 1))[0]

    if auth_version != 0x01:
        return False

    username_length = (await read_exact(reader, 1))[0]
    username = (await read_exact(reader, username_length)).decode(
        "utf-8", errors="ignore"
    )

    password_length = (await read_exact(reader, 1))[0]
    password = (await read_exact(reader, password_length)).decode(
        "utf-8", errors="ignore"
    )

    if username == USERNAME and password == PASSWORD:
        writer.write(b"\x01\x00")
        await writer.drain()
        return True

    writer.write(b"\x01\x01")
    await writer.drain()

    return False


async def handle_connect(reader, writer):
    version = (await read_exact(reader, 1))[0]
    command = (await read_exact(reader, 1))[0]
    reserved = (await read_exact(reader, 1))[0]
    address_type = (await read_exact(reader, 1))[0]

    if version != 0x05:
        return None

    # We only support TCP CONNECT.
    if command != 0x01:
        writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        return None

    if address_type == 0x01:
        # IPv4
        raw_address = await read_exact(reader, 4)
        destination = ".".join(str(x) for x in raw_address)

    elif address_type == 0x03:
        # Domain name
        length = (await read_exact(reader, 1))[0]
        destination = (await read_exact(reader, length)).decode(
            "idna", errors="ignore"
        )

    elif address_type == 0x04:
        # IPv6
        raw_address = await read_exact(reader, 16)
        destination = ":".join(
            f"{raw_address[i]:02x}{raw_address[i + 1]:02x}"
            for i in range(0, 16, 2)
        )

    else:
        writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        return None

    raw_port = await read_exact(reader, 2)
    destination_port = struct.unpack("!H", raw_port)[0]

    return destination, destination_port


async def relay(reader, writer):
    try:
        while True:
            data = await reader.read(65536)

            if not data:
                break

            writer.write(data)
            await writer.drain()

    except (ConnectionError, asyncio.CancelledError):
        pass


async def handle_client(reader, writer):
    remote_writer = None

    try:
        # SOCKS5 authentication
        authenticated = await asyncio.wait_for(
            authenticate(reader, writer),
            timeout=15,
        )

        if not authenticated:
            return

        # SOCKS5 CONNECT request
        target = await asyncio.wait_for(
            handle_connect(reader, writer),
            timeout=15,
        )

        if not target:
            return

        destination, destination_port = target

        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(
                    destination,
                    destination_port,
                ),
                timeout=15,
            )

        except Exception:
            # SOCKS5: General failure
            writer.write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return

        # SOCKS5 success response
        writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()

        # Bidirectional relay
        await asyncio.gather(
            relay(reader, remote_writer),
            relay(remote_reader, writer),
        )

    except (
        asyncio.IncompleteReadError,
        asyncio.TimeoutError,
        ConnectionError,
        BrokenPipeError,
    ):
        pass

    finally:
        if remote_writer:
            remote_writer.close()

            try:
                await remote_writer.wait_closed()
            except Exception:
                pass

        writer.close()

        try:
            await writer.wait_closed()
        except Exception:
            pass


async def main():
    server = await asyncio.start_server(
        handle_client,
        host="0.0.0.0",
        port=PORT,
        limit=65536,
    )

    addresses = ", ".join(str(sock.getsockname()) for sock in server.sockets)

    print(f"SOCKS5 server listening on {addresses}")
    print("Username/password authentication is enabled.")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
