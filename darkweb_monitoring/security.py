from fastapi import Depends, Header, HTTPException

from .config import Settings, get_settings


class Principal:
    def __init__(self, role: str):
        self.role = role


def require_user(
    x_api_key: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> Principal:
    if not settings.auth_enabled:
        return Principal(role="admin")
    if x_api_key in settings.allowed_admin_api_keys:
        return Principal(role="admin")
    if x_api_key in settings.allowed_api_keys:
        return Principal(role="analyst")
    raise HTTPException(status_code=401, detail="Missing or invalid API key")


def require_admin(principal: Principal = Depends(require_user)) -> Principal:
    if principal.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return principal

