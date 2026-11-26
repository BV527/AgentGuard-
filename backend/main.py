"""
FastAPI Main Application Entry Point for AgentGuard.
"""

from fastapi import FastAPI
from api.runtime_routes import router as runtime_router


app = FastAPI(
    title="AgentGuard Runtime API",
    description="Task-scoped agent execution and runtime security decisions.",
    version="2.0.0",
)

# Register API Router
app.include_router(runtime_router)


@app.get("/")
def root():
    return {
        "service": "AgentGuard Runtime API",
        "status": "ONLINE",
        "docs": "/docs"
    }
