import asyncio

import pydantic_ai as pai
from loguru import logger
from pydantic_ai.mcp import MCPServerHTTP
from pydantic_ai.models.gemini import GeminiModel
from pydantic_ai.providers.google_gla import GoogleGLAProvider

from prd_mcp.config import get_config

config = get_config()

server = MCPServerHTTP(
    url="http://0.0.0.0:8000/sse", timeout=100000, sse_read_timeout=100000
)
model = GeminiModel(
    "gemini-2.5-pro-exp-03-25",
    provider=GoogleGLAProvider(
        api_key=config.gemini_api_key,
    ),
)
agent = pai.Agent(
    model,
    system_prompt=(
        "Be brief, but use ridiculously flower language, like someone who overuses a thesaurus."
    ),
    mcp_servers=[server],
)

prd_prompt = """
Some inexperienced developers wrote a lot of code in direct communication with the user. You won't get another chance to get that kind of contact again, so now you have to figure out what the user's requirements are.

Based on the code base, write a detailed and comprehensive product requirements document.

Here is the code base:
```
{code_base}
```
""".strip()


async def main():
    async with agent.run_mcp_servers():
        with open("dev/code_base.txt") as file:
            code_base = file.read()
            logger.debug(len(code_base))
        response = await agent.run(prd_prompt.format(code_base=code_base))
        logger.debug(response.data)
        return response.data


if __name__ == "__main__":
    asyncio.run(main())
