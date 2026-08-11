import os
import subprocess
import sys

def main():
port = os.environ.get("PORT", "1080")
username = os.environ.get("USERNAME")
password = os.environ.get("PASSWORD")

```
if not username or not password:
    print("ERROR: USERNAME and PASSWORD must be set.", flush=True)
    sys.exit(1)

print(f"Starting SOCKS5 server on 0.0.0.0:{port}", flush=True)
print("Username/password authentication enabled.", flush=True)

command = [
    "asyncio_socks_server",
    "--host",
    "0.0.0.0",
    "--port",
    port,
    "--auth",
    f"{username}:{password}",
    "--log-level",
    "INFO",
]

process = subprocess.run(command)

sys.exit(process.returncode)
```

if **name** == "**main**":
main()
