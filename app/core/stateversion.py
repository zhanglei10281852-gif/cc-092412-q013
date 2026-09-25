from __future__ import annotations

"""角色权限变更所依赖的数据版本指纹。

预演、批准与正式应用之间，只要角色定义、角色权限、用户角色分配或在途业务
状态发生任何变化，指纹就会改变，旧预演结果随即失效，必须重新预演。

会话本身不纳入指纹：登录与退出属于高频事件，不改变“用户角色、权限或业务
状态”；预演时仍会把仍有效的会话完整写入快照，供人工核对与对账。
"""

import hashlib
import json
import sqlite3
from typing import Any

from app.repositories.base import rows_dict

_FINGERPRINT_KEYS = (
    "roles",
    "role_permissions",
    "user_roles",
    "users",
    "open_affairs",
    "open_petitions",
    "departments",
)


def _query(connection: sqlite3.Connection, key: str) -> list[dict[str, Any]]:
    if key == "roles":
        return rows_dict(connection.execute(
            "SELECT id,code,name,description,is_system,updated_at FROM roles ORDER BY id"
        ).fetchall())
    if key == "role_permissions":
        return rows_dict(connection.execute(
            "SELECT role_id,permission_id FROM role_permissions ORDER BY role_id,permission_id"
        ).fetchall())
    if key == "user_roles":
        return rows_dict(connection.execute(
            "SELECT user_id,role_id FROM user_roles ORDER BY user_id,role_id"
        ).fetchall())
    if key == "users":
        return rows_dict(connection.execute(
            "SELECT id,username,status,department_id FROM users ORDER BY id"
        ).fetchall())
    if key == "open_affairs":
        return rows_dict(connection.execute(
            "SELECT id,status,department_id,handler FROM affairs "
            "WHERE status IN ('待受理','办理中','已退回') ORDER BY id"
        ).fetchall())
    if key == "open_petitions":
        return rows_dict(connection.execute(
            "SELECT id,status,department_id FROM petitions "
            "WHERE status IN ('待签收','待分派','办理中','待审核','退回重办','复查中') ORDER BY id"
        ).fetchall())
    if key == "departments":
        return rows_dict(connection.execute(
            "SELECT id,name,is_active FROM departments ORDER BY id"
        ).fetchall())
    raise KeyError(key)


def snapshot_state(connection: sqlite3.Connection) -> dict[str, Any]:
    """返回受监控数据的完整快照（可保存、可人工核对）。

    快照除指纹口径数据外，还包含当时仍有效的会话列表。
    """
    snapshot = {key: _query(connection, key) for key in _FINGERPRINT_KEYS}
    snapshot["active_sessions"] = rows_dict(connection.execute(
        "SELECT s.id,s.user_id,u.username,s.client_label,s.issued_at,s.last_seen_at,s.expires_at "
        "FROM sessions s JOIN users u ON u.id=s.user_id "
        "WHERE s.revoked_at IS NULL ORDER BY s.id"
    ).fetchall())
    return snapshot


def fingerprint_state(connection: sqlite3.Connection, *, snapshot: dict[str, Any] | None = None) -> str:
    """对受监控数据计算确定性的 SHA-256 指纹（不含会话）。"""
    if snapshot is None:
        payload = [{key: _query(connection, key)} for key in _FINGERPRINT_KEYS]
    else:
        payload = [{key: snapshot.get(key, [])} for key in _FINGERPRINT_KEYS]
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
