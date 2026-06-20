"""FastAPI application factory for the Argus web UI."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from argus.web.api.cases import router as cases_router
from argus.web.api.chat import router as chat_router
from argus.web.api.settings import router as settings_router

# Look for built frontend in a few places
_CANDIDATES = [
    Path(__file__).parent / "static",  # packaged install
    Path.cwd() / "webui" / "dist",  # dev: run from project root
    Path(__file__).parents[4] / "webui" / "dist",  # editable install
]


def _find_static() -> Path | None:
    for p in _CANDIDATES:
        if p.exists() and (p / "index.html").exists():
            return p
    return None


def create_app() -> FastAPI:
    app = FastAPI(
        title="Argus CTI Platform",
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url=None,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(cases_router, prefix="/api/cases", tags=["cases"])
    app.include_router(chat_router, prefix="/api/chat", tags=["chat"])
    app.include_router(settings_router, prefix="/api", tags=["settings"])

    static_dir = _find_static()
    if static_dir is not None:
        assets = static_dir / "assets"
        if assets.exists():
            app.mount("/assets", StaticFiles(directory=str(assets)), name="assets")

        @app.get("/{full_path:path}", include_in_schema=False, response_model=None)
        async def spa_fallback(full_path: str) -> FileResponse | JSONResponse:
            if full_path.startswith("api/"):
                return JSONResponse({"error": "Not found"}, status_code=404)
            return FileResponse(str(static_dir / "index.html"))
    else:

        @app.get("/", include_in_schema=False)
        async def no_frontend() -> JSONResponse:
            return JSONResponse(
                {
                    "message": (
                        "Argus API is running."
                        " Build the frontend: cd webui && npm install && npm run build"
                    ),
                    "docs": "/api/docs",
                }
            )

    return app


app = create_app()
