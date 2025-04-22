import os, logging
from dotenv import load_dotenv
import openai

load_dotenv()
log   = logging.getLogger("alienrecon")
MODEL = "gpt-4o"        # sensible default

def get_client() -> openai.OpenAI:
    key = os.getenv("OPENAI_API_KEY")
    if not key:
        raise EnvironmentError("OPENAI_API_KEY not set")
    return openai.OpenAI(api_key=key)

def chat(history: list[dict], user_msg: str, sys_prompt: str) -> str:
    client = get_client()
    messages = [{"role": "system", "content": sys_prompt}] + history + [
        {"role": "user", "content": user_msg}
    ]
    res = client.chat.completions.create(
        model=MODEL,
        messages=messages,
        temperature=0.7,
    )
    return res.choices[0].message.content.strip()

