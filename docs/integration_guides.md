# Integration Guides

## LangChain

```python
from langchain.llms import OpenAI
from llmfirewall.client import LLMFirewallClient

firewall = LLMFirewallClient(base_url="http://localhost:8000", api_key="your-key")

class SafeLLM:
    def __init__(self, llm):
        self.llm = llm

    def __call__(self, prompt):
        result = firewall.moderate(prompt)
        if not result.allowed:
            return f"[BLOCKED: {', '.join(result.reasons)}]"
        return self.llm(prompt)

llm = SafeLLM(OpenAI())
print(llm("What is the capital of France?"))
```

## LlamaIndex

```python
from llama_index.core import VectorStoreIndex, SimpleDirectoryReader
from llmfirewall.client import LLMFirewallClient

firewall = LLMFirewallClient(base_url="http://localhost:8000", api_key="your-key")

# Custom callback that moderates queries before retrieval
def moderate_query(query):
    result = firewall.moderate(query)
    if not result.allowed:
        raise ValueError(f"Query blocked: {', '.join(result.reasons)}")
    return query

documents = SimpleDirectoryReader("data").load_data()
index = VectorStoreIndex.from_documents(documents)
query_engine = index.as_query_engine()

query = "What is the capital of France?"
moderate_query(query)  # raises if blocked
response = query_engine.query(query)
```

## OpenAI Proxy

```python
import openai
from llmfirewall.client import LLMFirewallClient

firewall = LLMFirewallClient(base_url="http://localhost:8000")

class FirewallWrapper:
    def __init__(self, original):
        self.original = original

    def chat_completions_create(self, *args, **kwargs):
        messages = kwargs.get("messages", [])
        for msg in messages:
            content = msg.get("content", "")
            result = firewall.moderate(content)
            if not result.allowed:
                return {"choices": [{"message": {"content": f"[BLOCKED: {', '.join(result.reasons)}]"}}]}
        return self.original.chat.completions.create(*args, **kwargs)

openai_client = openai.OpenAI()
safe_client = FirewallWrapper(openai_client)
```

## FastAPI Middleware

```python
from fastapi import FastAPI, Request
from llmfirewall.client import LLMFirewallClient

app = FastAPI()
firewall = LLMFirewallClient()

@app.middleware("http")
async def moderate_requests(request: Request, call_next):
    if request.method == "POST":
        body = await request.json()
        text = body.get("prompt", "")
        result = firewall.moderate(text)
        if not result.allowed:
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=403,
                content={"error": "Blocked", "reasons": result.reasons}
            )
    return await call_next(request)
```
