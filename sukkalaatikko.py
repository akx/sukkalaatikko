import argparse
import asyncio
import datetime
import json
import os.path
from asyncio import CancelledError, StreamReader, StreamWriter
from functools import partial
from secrets import token_hex

import aiofiles
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapNgWriter

OUT_PORT = 1234
IN_PORT = 5678
IN_IP = "127.0.0.2"
OUT_IP = "127.0.0.1"


async def proxy_one_direction(reader: StreamReader, writer: StreamWriter, callback):
    while True:
        data = await reader.read(65536)
        if not data:
            break
        await callback(data)
        writer.write(data)
        await writer.drain()
    writer.close()


async def write_packet_jsonl(jsonl_file, data, is_out):
    payload = ["out" if is_out else "in"]
    try:
        payload.append(data.decode("utf-8"))
    except UnicodeDecodeError:
        payload.append({"raw": data.hex()})
    await jsonl_file.write(json.dumps(payload, ensure_ascii=False) + "\n")


class ConversationWriter:
    def __init__(
        self,
        *,
        pcap_writer: PcapNgWriter,
        jsonl_file,
    ) -> None:
        self.pcap_writer = pcap_writer
        self.jsonl_file = jsonl_file
        self.buf = b""
        self.buf_is_out = None
        self.seq = 1000

    async def write(self, pkt: bytes, is_out: bool) -> None:
        if self.buf_is_out is None:
            self.buf_is_out = is_out
        elif self.buf_is_out != is_out:
            await self.flush()
        self.buf_is_out = is_out
        self.buf += pkt

    async def flush(self) -> None:
        buf = self.buf
        if buf:
            print(("<<<" if self.buf_is_out else ">>>"), buf)
            await write_packet_jsonl(self.jsonl_file, buf, self.buf_is_out)
            # await self.write_pcap(buf)
            self.buf = b""
            self.buf_is_out = None

    async def write_pcap(self, buf):
        sport, dport = (OUT_PORT, IN_PORT) if self.buf_is_out else (IN_PORT, OUT_PORT)
        sip, dip = (OUT_IP, IN_IP) if self.buf_is_out else (IN_IP, OUT_IP)
        pk = (
            Ether()
            / IP(src=sip, dst=dip)
            / TCP(sport=sport, dport=dport, flags="A")
            / Raw(buf)
        )
        self.pcap_writer.write(pk)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.flush()


async def async_main(proxy_socket: str, target_socket: str):
    if not os.path.exists(target_socket):
        raise FileNotFoundError(f"Target socket {target_socket} does not exist")

    async def connect_callback(
        source_reader: StreamReader,
        source_writer: StreamWriter,
    ):
        conversation_id = f"{datetime.datetime.now().isoformat()}-{token_hex(4)}"
        print("Starting conversation", conversation_id)
        with PcapNgWriter(f"data/{conversation_id}.pcapng") as pcap_writer:
            async with aiofiles.open(
                f"data/{conversation_id}.jsonl",
                mode="w",
            ) as jsonl_file:
                async with ConversationWriter(
                    pcap_writer=pcap_writer,
                    jsonl_file=jsonl_file,
                ) as cw:
                    target_reader, target_writer = await asyncio.open_unix_connection(
                        target_socket,
                    )
                    await asyncio.gather(
                        proxy_one_direction(
                            source_reader,
                            target_writer,
                            partial(cw.write, is_out=True),
                        ),
                        proxy_one_direction(
                            target_reader,
                            source_writer,
                            partial(cw.write, is_out=False),
                        ),
                    )
        print("Conversation ended", conversation_id)

    sock = await asyncio.start_unix_server(connect_callback, path=proxy_socket)
    async with sock:
        print(f"Listening on {proxy_socket}")
        try:
            await sock.serve_forever()
        except CancelledError:
            print("Stopping.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy-socket", "-p", type=str, required=True)
    parser.add_argument("--target-socket", "-t", type=str, required=True)

    args = parser.parse_args()

    asyncio.run(
        async_main(proxy_socket=args.proxy_socket, target_socket=args.target_socket),
    )


if __name__ == "__main__":
    main()
