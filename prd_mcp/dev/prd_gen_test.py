import asyncio

import pydantic_ai as pai
from httpx import AsyncClient
from loguru import logger
from pydantic_ai.models.gemini import GeminiModel
from pydantic_ai.providers.google_gla import GoogleGLAProvider
from pydantic_ai.settings import ModelSettings

from prd_mcp.config import get_config

config = get_config()

custom_http_client = AsyncClient(timeout=100000)
model = GeminiModel(
    "gemini-2.5-pro-exp-03-25",
    provider=GoogleGLAProvider(
        api_key=config.gemini_api_key,
        http_client=custom_http_client,
    ),
)
agent = pai.Agent(
    model,
    system_prompt=(
        "You are a technical product manager. You write comprehensive product requirements documents, which are enhanced by your deep technical expertise."
    ),
    model_settings=ModelSettings(timeout=100000),
)


prd_prompt = """
Some inexperienced developers wrote a lot of code in direct communication with the user. You won't get another chance to get that kind of contact again, so now you have to figure out what the user's requirements are.

Based on the code base, write a detailed and comprehensive product requirements document.

Here is the code base:
```
{code_base}
```
""".strip()


async def create_prd() -> str:
    """Create a new product requirements document based on the code base.

    Args:
        code_base: The code base to create the product requirements document from, in markdown format.
    """
    with open("dev/code_base.txt") as file:
        code_base = file.read()
        logger.debug(len(code_base))
    response = await agent.run(prd_prompt.format(code_base=code_base))
    logger.debug(response.data)
    return response.data


if __name__ == "__main__":
    asyncio.run(create_prd())
