from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.dependencies import current_principal
from app.core.security import Principal
from app.database import get_connection, transaction
from app.repositories.base import rows_dict
from app.repositories.identity import RoleRepository
from app.schemas.identity import RoleChangePreviewRequest, RoleCreate, RoleUpdate
from app.services.identity import IdentityService
from app.services.role_changes import RoleChangeService

router = APIRouter(prefix="/api/roles", tags=["角色权限"])


@router.get("")
def list_roles(principal: Principal = Depends(current_principal)) -> list[dict]:
    principal.require("roles.read")
    repository = RoleRepository(get_connection())
    roles = repository.list()
    for role in roles:
        role["permissions"] = repository.permissions(role["id"])
    return roles


@router.get("/permissions")
def list_permissions(principal: Principal = Depends(current_principal)) -> list[dict]:
    principal.require("roles.read")
    return rows_dict(get_connection().execute("SELECT * FROM permissions ORDER BY resource,action").fetchall())


@router.post("", status_code=201)
def create_role(data: RoleCreate, principal: Principal = Depends(current_principal)) -> dict:
    with transaction(immediate=True) as connection:
        return IdentityService(connection).create_role(principal, data.model_dump())


@router.post("/{role_ref}/rehearsals", status_code=201)
def create_role_rehearsal(
    role_ref: str,
    data: RoleChangePreviewRequest,
    principal: Principal = Depends(current_principal),
) -> dict:
    with transaction(immediate=True) as connection:
        service = RoleChangeService(connection)
        role_id = service.resolve_role_id(role_ref)
        return service.create_rehearsal(principal, role_id, data.model_dump())


@router.get("/{role_ref}")
def get_role(role_ref: str, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("roles.read")
    role_id = RoleChangeService(get_connection()).resolve_role_id(role_ref)
    return IdentityService(get_connection()).role_detail(role_id)


@router.patch("/{role_ref}")
def update_role(role_ref: str, data: RoleUpdate, principal: Principal = Depends(current_principal)) -> dict:
    # 权限集合的调整必须走“预演 → 确认 → 应用”流程，避免无预警地收回能力。
    if data.permission_codes is not None:
        from app.core.errors import ValidationError

        raise ValidationError("角色权限调整必须先生成变更预演，请使用 /api/roles/{role_id}/rehearsals 流程")
    with transaction(immediate=True) as connection:
        role_id = RoleChangeService(connection).resolve_role_id(role_ref)
        return IdentityService(connection).update_role(principal, role_id, data.model_dump(exclude_unset=True))
