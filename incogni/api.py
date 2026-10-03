"""Authenticated local dashboard and JSON control API."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Path as PathParam,
    Request,
    Response,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from incogni.approvals import ApprovalManager
from incogni.auth import LoginThrottle, OperatorAuth, Session
from incogni.dashboard import DASHBOARD_HTML
from incogni.drop import DropCompanion
from incogni.jobs import DurableJobQueue
from incogni.manual_assist import MANUAL_STEPS, ManualAssist
from incogni.service_config import ServiceConfig
from incogni.storage import ServiceStore, utciso


MAX_REQUEST_BODY_BYTES = 64 * 1024


class RequestBodyLimitMiddleware:
    def __init__(self, app, *, max_bytes: int = MAX_REQUEST_BODY_BYTES):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers", []))
        try:
            content_length = int(headers.get(b"content-length", b"0"))
        except ValueError:
            content_length = 0
        if content_length > self.max_bytes:
            await self._reject(scope, receive, send)
            return

        messages = []
        received = 0
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] == "http.disconnect":
                return
            received += len(message.get("body", b""))
            if received > self.max_bytes:
                await self._reject(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        async def replay_receive():
            if messages:
                return messages.pop(0)
            return {"type": "http.disconnect"}

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _reject(scope, receive, send):
        await JSONResponse(
            status_code=413, content={"detail": "request body too large"}
        )(scope, receive, send)


class StrictBody(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginBody(StrictBody):
    password: str = Field(min_length=1, max_length=1024)


class RetryBody(StrictBody):
    job_id: str = Field(min_length=1, max_length=128)


class DropBody(StrictBody):
    enrolled: bool
    terms_acknowledged: bool
    identifier: str | None = Field(default=None, max_length=512)


class ManualFoundBody(StrictBody):
    profile_id: str = Field(default="owner", min_length=1, max_length=128)
    additional: bool = False


def create_app(store: ServiceStore, config: ServiceConfig) -> FastAPI:
    auth = OperatorAuth(
        config.admin_password_hash,
        config.signing_key,
        ttl_seconds=config.session_ttl_seconds,
    )
    queue = DurableJobQueue(store)
    approval_manager = ApprovalManager(store)
    login_throttle = LoginThrottle()
    app = FastAPI(title="Personal Privacy Service", docs_url=None, redoc_url=None)
    app.add_middleware(RequestBodyLimitMiddleware)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'"
        )
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, exc: RequestValidationError):
        detail = [
            {
                "type": error.get("type", "validation_error"),
                "loc": error.get("loc", ()),
                "msg": error.get("msg", "Invalid request"),
            }
            for error in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": detail})

    def require_session(
        incogni_session: str | None = Cookie(default=None),
    ) -> Session:
        session = auth.verify_session(incogni_session or "")
        if session is None or not store.session_is_active(
            session.session_id, session.expires_at
        ):
            raise HTTPException(status_code=401, detail="authentication required")
        return session

    def require_csrf(
        session: Session = Depends(require_session),
        x_csrf_token: str | None = Header(default=None),
    ) -> Session:
        if not x_csrf_token or x_csrf_token != session.csrf_token:
            raise HTTPException(status_code=403, detail="invalid CSRF token")
        return session

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/login")
    def login(body: LoginBody, request: Request, response: Response) -> dict[str, Any]:
        client_key = request.client.host if request.client else "local"
        verified = login_throttle.authenticate(
            client_key, lambda: auth.verify_password(body.password)
        )
        if verified is None:
            raise HTTPException(
                status_code=429,
                detail="login temporarily throttled",
                headers={"Retry-After": "300"},
            )
        if not verified:
            raise HTTPException(status_code=401, detail="invalid credentials")
        token, session = auth.issue_session()
        store.register_session(session.session_id, session.expires_at)
        response.set_cookie(
            "incogni_session",
            token,
            httponly=True,
            secure=config.secure_cookies,
            samesite="strict",
            max_age=config.session_ttl_seconds,
            path="/",
        )
        store.record_audit("operator_login", "session", "operator")
        return {"csrf_token": session.csrf_token, "expires_at": session.expires_at}

    @app.post("/api/logout")
    def logout(
        response: Response, session: Session = Depends(require_csrf)
    ) -> dict[str, bool]:
        store.revoke_session(session.session_id)
        response.delete_cookie(
            "incogni_session",
            path="/",
            secure=config.secure_cookies,
            httponly=True,
            samesite="strict",
        )
        store.record_audit("operator_logout", "session", "operator")
        return {"ok": True}

    @app.get("/api/session")
    def session_info(session: Session = Depends(require_session)) -> dict[str, Any]:
        return {"csrf_token": session.csrf_token, "expires_at": session.expires_at}

    @app.get("/api/status")
    def status(_: Session = Depends(require_session)) -> dict[str, Any]:
        health = store.health()
        health.update(
            {
                "findings": store.conn.execute(
                    "SELECT count(*) FROM findings"
                ).fetchone()[0],
                "requests": store.conn.execute(
                    "SELECT count(*) FROM removal_requests"
                ).fetchone()[0],
                "blocked_jobs": store.conn.execute(
                    "SELECT count(*) FROM jobs WHERE status='blocked'"
                ).fetchone()[0],
                "drop_enrolled": store.get_setting("drop_enrolled", "false") == "true",
            }
        )
        return health

    @app.get("/api/jobs")
    def jobs(_: Session = Depends(require_session)) -> list[dict[str, Any]]:
        rows = store.conn.execute(
            "SELECT id,kind,broker_id,status,attempts,max_attempts,available_at,"
            "last_error_code,updated_at FROM jobs ORDER BY created_at DESC LIMIT 200"
        ).fetchall()
        return [dict(row) for row in rows]

    @app.get("/api/approvals")
    def approvals(_: Session = Depends(require_session)) -> list[dict[str, Any]]:
        rows = store.conn.execute(
            "SELECT id,request_id,job_id,action,status,expires_at,created_at,"
            "expires_at<=? AS expired FROM approvals WHERE status='pending' "
            "ORDER BY created_at",
            (datetime.now(timezone.utc).isoformat(),),
        ).fetchall()
        return [{**dict(row), "expired": bool(row["expired"])} for row in rows]

    @app.post("/api/approvals/{approval_id}/approve")
    def approve(
        approval_id: str = PathParam(min_length=1, max_length=128),
        _: Session = Depends(require_csrf),
    ) -> dict[str, bool]:
        try:
            approval_manager.decide_and_release(approval_id, approved=True)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"ok": True}

    @app.post("/api/approvals/{approval_id}/reject")
    def reject(
        approval_id: str = PathParam(min_length=1, max_length=128),
        _: Session = Depends(require_csrf),
    ) -> dict[str, bool]:
        try:
            approval_manager.decide_and_release(approval_id, approved=False)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"ok": True}

    @app.post("/api/approvals/{approval_id}/reissue")
    def reissue(
        approval_id: str = PathParam(min_length=1, max_length=128),
        _: Session = Depends(require_csrf),
    ) -> dict[str, Any]:
        try:
            replacement = approval_manager.reissue(approval_id)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"ok": True, "approval_id": replacement}

    @app.post("/api/manual/{broker_id}/found")
    def manual_found(
        body: ManualFoundBody,
        broker_id: str = PathParam(min_length=1, max_length=128),
        _: Session = Depends(require_csrf),
    ) -> dict[str, Any]:
        try:
            result = ManualAssist(store).record_found(
                broker_id,
                profile_id=body.profile_id,
                additional=body.additional,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="broker flow not found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"ok": True, **result}

    @app.get("/api/requests/{request_id}/manual")
    def manual_checklist(
        request_id: str = PathParam(min_length=1, max_length=128),
        _: Session = Depends(require_session),
    ) -> dict[str, Any]:
        try:
            return ManualAssist(store).checklist(request_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="request not found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/requests/{request_id}/manual/{step}")
    def manual_step(
        request_id: str = PathParam(min_length=1, max_length=128),
        step: str = PathParam(pattern="^(" + "|".join(MANUAL_STEPS) + ")$"),
        _: Session = Depends(require_csrf),
    ) -> dict[str, Any]:
        try:
            status = ManualAssist(store).record(request_id, step)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="request not found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"ok": True, "status": status}

    @app.post("/api/retry")
    def retry(body: RetryBody, _: Session = Depends(require_csrf)) -> dict[str, bool]:
        try:
            queue.retry(body.job_id)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        store.record_audit("job_retried", "job", body.job_id)
        return {"ok": True}

    @app.post("/api/pause")
    def pause(_: Session = Depends(require_csrf)) -> dict[str, bool]:
        store.set_setting("emergency_stop", "true")
        store.record_audit("emergency_stop_enabled", "service", "local")
        return {"emergency_stop": True}

    @app.post("/api/resume")
    def resume(_: Session = Depends(require_csrf)) -> dict[str, bool]:
        store.set_setting("emergency_stop", "false")
        store.record_audit("emergency_stop_disabled", "service", "local")
        return {"emergency_stop": False}

    @app.get("/api/drop")
    def drop_status(_: Session = Depends(require_session)) -> dict[str, Any]:
        return {
            "enrolled": store.get_setting("drop_enrolled", "false") == "true",
            "terms_acknowledged": store.get_setting("drop_terms_ack", "false") == "true",
            "updated_at": store.get_setting("drop_updated_at"),
            "consumer_url": "https://privacy.ca.gov/drop/",
        }

    @app.post("/api/drop")
    def update_drop(body: DropBody, _: Session = Depends(require_csrf)) -> dict[str, Any]:
        if body.enrolled and not body.terms_acknowledged:
            raise HTTPException(
                status_code=422, detail="terms acknowledgment is required"
            )
        if body.enrolled:
            DropCompanion(store).record_enrollment(
                terms_acknowledged=body.terms_acknowledged,
                drop_identifier=body.identifier,
            )
        else:
            store.set_setting("drop_enrolled", "false")
            store.set_setting("drop_terms_ack", "false")
            store.set_setting("drop_updated_at", utciso())
            store.record_audit("drop_status_updated", "drop", "owner")
        return {"enrolled": body.enrolled}

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> str:
        return DASHBOARD_HTML

    return app
