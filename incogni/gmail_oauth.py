"""Human-triggered Gmail OAuth consent with minimal scopes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from incogni.storage import ServiceStore

GMAIL_SCOPES = (
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
)


def authorize_gmail(
    store: ServiceStore,
    client_secret_file: Path,
    *,
    flow_factory: Any | None = None,
) -> None:
    """Run local browser consent and encrypt the resulting refresh credentials."""

    if flow_factory is None:
        from google_auth_oauthlib.flow import InstalledAppFlow

        flow_factory = InstalledAppFlow
    flow = flow_factory.from_client_secrets_file(
        str(client_secret_file), scopes=list(GMAIL_SCOPES)
    )
    credentials = flow.run_local_server(port=0, open_browser=True)
    payload = json.loads(credentials.to_json())
    store.put_secret("gmail_oauth", payload)
    store.record_audit("gmail_oauth_authorized", "integration", "gmail")
