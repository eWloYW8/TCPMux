import asyncio
import websockets
import sys

async def nc_style_ws(uri):
    async with websockets.connect(uri) as ws:
        async def send_stdin():
            loop = asyncio.get_event_loop()
            while True:
                line = await loop.run_in_executor(None, sys.stdin.readline)
                if not line:
                    break
                await ws.send(line.rstrip("\n"))

        async def recv_ws():
            async for message in ws:
                print(message)

        await asyncio.gather(send_stdin(), recv_ws())

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"用法: python {sys.argv[0]} ws://127.0.0.1:port/path")
        sys.exit(1)

    uri = sys.argv[1]
    asyncio.run(nc_style_ws(uri))
