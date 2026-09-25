from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.dependencies import current_principal
from app.core.security import Principal
from app.database import get_connection, transaction
from app.schemas.identity import RoleChangePreviewCreate
from app.services.role_changes import RoleChangeService

router = APIRouter(prefix="/api/roles", tags=["角色变更预演"])
preview_router = APIRouter(prefix="/api/role-change-previews", tags=["角色变更预演"])


@router.post("/{role_id}/change-previews", status_code=201)
def create_preview(role_id: int, data: RoleChangePreviewCreate, principal: Principal = Depends(current_principal)) -> dict:
    with transaction(immediate=True) as connection:
        return RoleChangeService(connection).create_preview(principal, role_id, data.permission_codes)


@router.get("/{role_id}/change-previews")
def list_previews(role_id: int, principal: Principal = Depends(current_principal)) -> list[dict]:
    return RoleChangeService(get_connection()).list_for_role(principal, role_id)


@preview_router.get("/{preview_id}")
def get_preview(preview_id: int, principal: Principal = Depends(current_principal)) -> dict:
    return RoleChangeService(get_connection()).get_preview(principal, preview_id)


@preview_router.post("/{preview_id}/confirm")
def confirm_preview(preview_id: int, principal: Principal = Depends(current_principal)) -> dict:
    # 先在自动提交模式下校验数据版本：若已变化，失效标记与审计会随 409 一起落库
    RoleChangeService(get_connection()).check_freshness(principal, preview_id)
    with transaction(immediate=True) as connection:
        return RoleChangeService(connection).confirm(principal, preview_id)


@preview_router.post("/{preview_id}/apply")
def apply_preview(preview_id: int, principal: Principal = Depends(current_principal)) -> dict:
    RoleChangeService(get_connection()).check_freshness(principal, preview_id)
    with transaction(immediate=True) as connection:
        return RoleChangeService(connection).apply(principal, preview_id)


@preview_router.post("/{preview_id}/cancel")
def cancel_preview(preview_id: int, principal: Principal = Depends(current_principal)) -> dict:
    with transaction(immediate=True) as connection:
        return RoleChangeService(connection).cancel(principal, preview_id)
