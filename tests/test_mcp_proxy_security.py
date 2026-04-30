import asyncio

from aiohttp import web

from sentinel.mcp_proxy import _strip_server_header


def test_proxy_response_prepare_strips_server_header():
    response = web.Response(headers={"Server": "Python/3.12 aiohttp/3.13.5"})

    asyncio.run(_strip_server_header(None, response))

    assert "Server" not in response.headers
