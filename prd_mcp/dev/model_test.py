import asyncio

import pydantic_ai as pai
from pydantic_ai.models.gemini import GeminiModel
from pydantic_ai.providers.google_gla import GoogleGLAProvider

from prd_mcp.config import get_config

config = get_config()

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
)


async def main():
    response = await agent.run("Hello, how are you?")
    print(response)


if __name__ == "__main__":
    asyncio.run(main())
