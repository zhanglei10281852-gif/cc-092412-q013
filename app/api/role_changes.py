from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import current_principal
from app.core.security import Principal
from app.database import get_connection, transaction
from app.schemas.identity import RoleChangeDecisionRequest
from app.services.role_changes import RoleChangeService

router = APIRouter(prefix="/api/role-changes", tags=["角色权限变更预演"])


@router.get("")
def list_rehearsals(
    status: str | None = Query(default=None),
    principal: Principal = Depends(current_principal),
) -> list[dict]:
    return RoleChangeService(get_connection()).list_rehearsals(principal, status)


@router.get("/{rehearsal_id}")
def get_rehearsal(rehearsal_id: int, principal: Principal = Depends(current_principal)) -> dict:
    return RoleChangeService(get_connection()).get_detail(principal, rehearsal_id)


@router.post("/{rehearsal_id}/approve")
def approve_rehearsal(
    rehearsal_id: int,
    data: RoleChangeDecisionRequest | None = None,
    principal: Principal = Depends(current_principal),
) -> dict:
    comment = data.comment if data is not None else ""
    with transaction(immediate=True) as connection:
        return RoleChangeService(connection).decide(principal, rehearsal_id, "approved", comment)


@router.post("/{rehearsal_id}/reject")
def reject_rehearsal(
    rehearsal_id: int,
    data: RoleChangeDecisionRequest | None = None,
    principal: Principal = Depends(current_principal),
) -> dict:
    comment = data.comment if data is not None else ""
    with transaction(immediate=True) as connection:
        return RoleChangeService(connection).decide(principal, rehearsal_id, "rejected", comment)


@router.post("/{rehearsal_id}/apply")
def apply_rehearsal(rehearsal_id: int, principal: Principal = Depends(current_principal)) -> dict:
    with transaction(immediate=True) as connection:
        return RoleChangeService(connection).apply(principal, rehearsal_id)
