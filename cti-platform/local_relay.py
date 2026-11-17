"""Publish local HTTPS without giving CTI's isolated container a public route."""

import asyncio


async def forward(reader, writer):
    while data := await asyncio.wait_for(reader.read(65536), timeout=240):
        writer.write(data)
        await asyncio.wait_for(writer.drain(), timeout=30)
    writer.write_eof()


async def relay(client_reader, client_writer):
    upstream_writer = None
    tasks = []
    try:
        upstream_reader, upstream_writer = await asyncio.wait_for(
            asyncio.open_connection("cti", 5001), timeout=5
        )
        tasks = [
            asyncio.create_task(forward(client_reader, upstream_writer)),
            asyncio.create_task(forward(upstream_reader, client_writer)),
        ]
        await asyncio.gather(*tasks)
    except (OSError, TimeoutError):
        pass
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for writer in (client_writer, upstream_writer):
            if writer is not None:
                writer.close()


async def main():
    async with await asyncio.start_server(relay, "0.0.0.0", 5001) as server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
