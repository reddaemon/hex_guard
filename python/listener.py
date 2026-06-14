import importlib
import tomllib
import logging
import signal
import subprocess
import sys
from pathlib import Path

from telethon import TelegramClient, events

import grpc

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("hex_guard_listener")

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROTO_DIR = _SCRIPT_DIR.parent / "proto"
_PB2_FILE = _SCRIPT_DIR / "hex_guard_pb2.py"
_GRPC_FILE = _SCRIPT_DIR / "hex_guard_pb2_grpc.py"


def _ensure_stubs():
    """Generate protobuf stubs if they don't exist."""
    if _PB2_FILE.exists() and _GRPC_FILE.exists():
        return

    log.info("Generating gRPC stubs...")
    cmd = [
        sys.executable,
        "-m",
        "grpc_tools.protoc",
        f"-I{_PROTO_DIR}",
        f"--python_out={_SCRIPT_DIR}",
        f"--grpc_python_out={_SCRIPT_DIR}",
        str(_PROTO_DIR / "hex_guard.proto"),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"protoc failed: {result.stderr}")
    log.info("gRPC stubs generated")


def load_config() -> dict:
    config_path = _SCRIPT_DIR / "config.toml"
    with open(config_path, "rb") as f:
        return tomllib.load(f)


class GracefulShutdown:
    def __init__(self):
        self._event = signal.Event()

    def set(self):
        self._event.set()

    def wait(self):
        self._event.wait()


def main():
    _ensure_stubs()

    # Add script dir to path and import generated stubs
    if str(_SCRIPT_DIR) not in sys.path:
        sys.path.insert(0, str(_SCRIPT_DIR))

    hex_guard_pb2 = importlib.import_module("hex_guard_pb2")
    hex_guard_pb2_grpc = importlib.import_module("hex_guard_pb2_grpc")

    config = load_config()

    phone = config["listener"]["phone"]
    session_dir = config["listener"]["session_dir"]
    blacklist = set(config["filter"]["blacklist_chats"])
    grpc_addr = config["grpc"]["server_addr"]

    if not phone:
        log.error("phone not set in config.toml")
        sys.exit(1)

    session_path = _SCRIPT_DIR / session_dir
    session_path.mkdir(exist_ok=True)

    channel = grpc.insecure_channel(grpc_addr)
    stub = hex_guard_pb2_grpc.HexGuardStub(channel)
    shutdown = GracefulShutdown()

    def handle_signal(signum, frame):
        log.info("Received shutdown signal")
        shutdown.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    client = TelegramClient(session_path / "hex_guard_session", api_id=0, api_hash="")

    @client.on(events.NewMessage())
    async def handler(event):
        chat_id = event.chat_id if event.chat_id else 0
        if chat_id in blacklist:
            log.debug(f"Skipping blacklisted chat {chat_id}")
            return

        text = event.message.text or ""
        sender_id = event.sender_id if event.sender else 0
        sender_name = event.sender.first_name if event.sender else "Unknown"

        log.debug(
            f"Analyzing: chat={chat_id}, sender={sender_name}, text={text[:100]}"
        )

        try:
            msg = hex_guard_pb2.Message(
                chat_id=chat_id,
                text=text,
                sender_id=sender_id,
                sender_name=sender_name,
            )
            result = stub.AnalyzeMessage(msg)
            if result.score > 0 or result.zones:
                log.info(
                    f"Result: score={result.score}, zones={result.zones}, chat={chat_id}"
                )
        except grpc.RpcError as e:
            log.error(f"gRPC error: {e}")

    log.info("Starting Telethon listener, connecting to Telegram...")
    client.start(phone=phone)
    log.info("Connected. Listening for messages...")

    try:
        client.run_until_disconnected()
    except KeyboardInterrupt:
        pass
    finally:
        channel.close()
        log.info("Listener stopped")


if __name__ == "__main__":
    main()
