
import asyncio
import os
import struct

USERNAME = os.environ.get("USERNAME")
PASSWORD = os.environ.get("PASSWORD")
PORT = int(os.environ.get("PORT", "1080"))

if not USERNAME or not PASSWORD:
    raise RuntimeError("USERNAME and PASSWORD environment variables are required")


async def read_exact(reader, size):
    return await reader.readexactly(size)


async def authenticate(reader, writer):
    version = (await read_exact(reader, 1))[0]

    if version != 5:
        print(f"Invalid SOCKS version: {version}", flush=True)
        return False

    nmethods = (await read_exact(reader, 1))[0]
    methods = await read_exact(reader, nmethods)

    print(
        f"SOCKS5 authentication methods offered: {list(methods)}",
        flush=True,
    )

    if 2 not in methods:
        writer.write(b"\x05\xff")
        await writer.drain()
        return False

    writer.write(b"\x05\x02")
    await writer.drain()

    auth_version = (await read_exact(reader, 1))[0]

    if auth_version != 1:
        print(
            f"Invalid username/password auth version: {auth_version}",
            flush=True,
        )
        return False

    username_length = (await read_exact(reader, 1))[0]
    username = (await read_exact(reader, username_length)).decode(
        "utf-8",
        errors="replace",
    )

    password_length = (await read_exact(reader, 1))[0]
    password = (await read_exact(reader, password_length)).decode(
        "utf-8",
        errors="replace",
    )

    if username == USERNAME and password == PASSWORD:
        writer.write(b"\x01\x00")
        await writer.drain()

        print(
            "Authentication successful: "
            f"{writer.get_extra_info('peername')}",
            flush=True,
        )

        return True

    writer.write(b"\x01\x01")
    await writer.drain()

    print(
        "Authentication failed: "
        f"{writer.get_extra_info('peername')}",
        flush=True,
    )

    return False


async def handle_connect(reader, writer):
    version = (await read_exact(reader, 1))[0]
    command = (await read_exact(reader, 1))[0]
    reserved = (await read_exact(reader, 1))[0]
    address_type = (await read_exact(reader, 1))[0]

    print(
        f"SOCKS5 request: version={version}, "
        f"command={command}, reserved={reserved}, "
        f"address_type={address_type}",
        flush=True,
    )

    if version != 5:
        return None

    command_names = {
        1: "CONNECT",
        2: "BIND",
        3: "UDP ASSOCIATE",
    }

    command_name = command_names.get(
        command,
        f"UNKNOWN({command})",
    )

    print(
        f"SOCKS5 command received: {command_name}",
        flush=True,
    )

    if command != 1:
        print(
            f"Unsupported SOCKS5 command: {command_name}",
            flush=True,
        )

        writer.write(
            b"\x05\x07\x00\x01"
            b"\x00\x00\x00\x00"
            b"\x00\x00"
        )
        await writer.drain()

        return None

    if address_type == 1:
        raw_address = await read_exact(reader, 4)

        destination = ".".join(
            str(x) for x in raw_address
        )

    elif address_type == 3:
        length = (await read_exact(reader, 1))[0]

        raw_domain = await read_exact(
            reader,
            length,
        )

        try:
            destination = raw_domain.decode("ascii")

        except UnicodeDecodeError:
            destination = raw_domain.decode(
                "utf-8",
                errors="replace",
            )

    elif address_type == 4:
        raw_address = await read_exact(reader, 16)

        groups = [
            f"{raw_address[i]:02x}{raw_address[i + 1]:02x}"
            for i in range(0, 16, 2)
        ]

        destination = ":".join(groups)

    else:
        print(
            f"Unsupported SOCKS5 address type: {address_type}",
            flush=True,
        )

        writer.write(
            b"\x05\x08\x00\x01"
            b"\x00\x00\x00\x00"
            b"\x00\x00"
        )
        await writer.drain()

        return None

    raw_port = await read_exact(
        reader,
        2,
    )

    destination_port = struct.unpack(
        "!H",
        raw_port,
    )[0]

    print(
        f"Requested destination: "
        f"{destination}:{destination_port}",
        flush=True,
    )

    return destination, destination_port


async def relay(reader, writer):
    try:
        while True:
            data = await reader.read(65536)

            if not data:
                break

            writer.write(data)
            await writer.drain()

    except (
        ConnectionError,
        asyncio.CancelledError,
    ):
        pass


async def handle_client(reader, writer):
    remote_writer = None

    peer = writer.get_extra_info(
        "peername"
    )

    print(
        f"New SOCKS5 connection: {peer}",
        flush=True,
    )

    try:
        authenticated = await asyncio.wait_for(
            authenticate(
                reader,
                writer,
            ),
            timeout=15,
        )

        if not authenticated:
            return

        target = await asyncio.wait_for(
            handle_connect(
                reader,
                writer,
            ),
            timeout=15,
        )

        if not target:
            print(
                f"Invalid CONNECT request: {peer}",
                flush=True,
            )
            return

        destination, destination_port = target

        print(
            f"CONNECT "
            f"{destination}:{destination_port} "
            f"from {peer}",
            flush=True,
        )

        try:
            remote_reader, remote_writer = (
                await asyncio.wait_for(
                    asyncio.open_connection(
                        destination,
                        destination_port,
                    ),
                    timeout=15,
                )
            )

        except Exception as exc:
            print(
                f"Connection failed to "
                f"{destination}:{destination_port} - "
                f"{type(exc).__name__}: {exc}",
                flush=True,
            )

            writer.write(
                b"\x05\x01\x00\x01"
                b"\x00\x00\x00\x00"
                b"\x00\x00"
            )

            await writer.drain()

            return

        writer.write(
            b"\x05\x00\x00\x01"
            b"\x00\x00\x00\x00"
            b"\x00\x00"
        )

        await writer.drain()

        print(
            f"Connected to "
            f"{destination}:{destination_port}",
            flush=True,
        )

        await asyncio.gather(
            relay(
                reader,
                remote_writer,
            ),
            relay(
                remote_reader,
                writer,
            ),
        )

    except asyncio.IncompleteReadError:
        print(
            f"Client disconnected during handshake: "
            f"{peer}",
            flush=True,
        )

    except asyncio.TimeoutError:
        print(
            f"SOCKS5 handshake timeout: {peer}",
            flush=True,
        )

    except ConnectionError as exc:
        print(
            f"Connection error from {peer}: "
            f"{type(exc).__name__}: {exc}",
            flush=True,
        )

    except Exception as exc:
        print(
            f"Unhandled error from {peer}: "
            f"{type(exc).__name__}: {exc}",
            flush=True,
        )

    finally:
        if remote_writer is not None:
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

        print(
            f"Connection closed: {peer}",
            flush=True,
        )


async def main():
    server = await asyncio.start_server(
        handle_client,
        "0.0.0.0",
        PORT,
        limit=65536,
    )

    print(
        f"SOCKS5 server listening on "
        f"('0.0.0.0', {PORT})",
        flush=True,
    )

    print(
        "Username/password authentication "
        "is enabled.",
        flush=True,
    )

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
