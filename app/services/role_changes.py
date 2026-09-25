from __future__ import annotations

"""角色权限变更预演、双人批准与带版本校验的正式应用。

流程：
1. 发起人提交目标角色的完整权限清单，服务在确定的数据版本上生成影响预演并保存；
2. 只要预演包含权限收回即为高风险，必须由另一位具备 roles.write 的管理员确认；
3. 批准或应用时重算数据版本指纹，角色、权限、用户角色或在途业务一旦变化即拒绝旧结果；
4. 应用成功后撤销失权用户的旧会话，并写入预演、批准与实际变化的对账记录。
"""

import json
import sqlite3
from collections import defaultdict
from datetime import timedelta
from typing import Any

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import ConflictError, NotFoundError, PermissionDeniedError, ValidationError
from app.core.security import Principal
from app.core.stateversion import fingerprint_state, snapshot_state
from app.repositories.base import row_dict, rows_dict
from app.services.audit import AuditContext, AuditService

REHEARSAL_TTL_MINUTES = 60

# 在途业务状态：尚未办结、仍需要人员继续办理。
OPEN_AFFAIR_STATUSES = ("待受理", "办理中", "已退回")
OPEN_PETITION_STATUSES = ("待签收", "待分派", "办理中", "待审核", "退回重办", "复查中")

# 待办类型与办理权限的对应关系。
TODO_PERMISSION_BUSINESS: dict[str, str] = {
    "affairs.write": "政务事务",
    "petitions.write": "信访件",
}


class RoleChangeService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.audit = AuditService(connection, self.clock)

    # ------------------------------------------------------------------ 预演

    def create_rehearsal(self, principal: Principal, role_id: int, data: dict) -> dict:
        principal.require("roles.write")
        role = self._require_role(role_id)
        base_codes = self._role_permission_codes(role_id)
        requested_codes = self._resolve_permission_codes(data.get("permission_codes", []))

        requested_name = data.get("name")
        requested_description = data.get("description")
        if requested_name is not None and not requested_name.strip():
            raise ValidationError("角色名称不能为空")

        added = sorted(set(requested_codes) - set(base_codes))
        removed = sorted(set(base_codes) - set(requested_codes))
        is_high_risk = bool(removed)

        snapshot = snapshot_state(self.connection)
        version = fingerprint_state(self.connection, snapshot=snapshot)
        impact = self._compute_impact(
            role=role,
            base_codes=set(base_codes),
            requested_codes=set(requested_codes),
            added=added,
            removed=removed,
        )

        now = self.clock.now()
        now_text = to_storage(now)
        cursor = self.connection.execute(
            "INSERT INTO role_change_rehearsals(role_id,role_code,requested_name,requested_description,"
            "base_permissions_json,requested_permissions_json,added_permissions_json,removed_permissions_json,"
            "is_high_risk,impact_json,state_snapshot_json,state_version,status,created_by,created_by_name,"
            "request_comment,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                role_id, role["code"],
                requested_name.strip() if requested_name is not None else None,
                requested_description,
                json.dumps(base_codes, ensure_ascii=False),
                json.dumps(requested_codes, ensure_ascii=False),
                json.dumps(added, ensure_ascii=False),
                json.dumps(removed, ensure_ascii=False),
                1 if is_high_risk else 0,
                json.dumps(impact, ensure_ascii=False, sort_keys=True),
                json.dumps(snapshot, ensure_ascii=False, sort_keys=True),
                version,
                "awaiting_approval",
                principal.user_id, principal.display_name,
                data.get("comment", "") or "",
                now_text,
                to_storage(now + timedelta(minutes=REHEARSAL_TTL_MINUTES)),
            ),
        )
        rehearsal_id = int(cursor.lastrowid)

        if is_high_risk:
            # 高风险变更保持 awaiting_approval，等待另一位管理员确认；
            # 发起人本人的确认会在 decide() 中被拒绝。
            pass
        else:
            # 纯新增（或仅文案）变更按策略无需第二人确认，登记一条自动批准记录。
            self._record_decision(
                rehearsal_id, principal, "approved",
                "变更不包含权限收回，按策略免第二人确认", version, now_text,
            )
            self.connection.execute(
                "UPDATE role_change_rehearsals SET status='approved',approved_by=?,approved_by_name=?,"
                "approved_at=?,approve_comment=? WHERE id=?",
                (principal.user_id, principal.display_name, now_text,
                 "变更不包含权限收回，按策略免第二人确认", rehearsal_id),
            )

        self.audit.record(
            AuditContext(principal.user_id, principal.display_name),
            action="role.change.rehearse",
            resource_type="role_change_rehearsal",
            resource_id=rehearsal_id,
            after={"role_code": role["code"], "added": added, "removed": removed, "is_high_risk": is_high_risk},
            metadata={"state_version": version, "impact_summary": impact["summary"]},
        )
        return self.detail(rehearsal_id)

    # ------------------------------------------------------------------ 批准

    def decide(self, principal: Principal, rehearsal_id: int, decision: str, comment: str) -> dict:
        principal.require("roles.write")
        rehearsal = self._require_rehearsal(rehearsal_id)
        self._ensure_fresh(rehearsal)
        if rehearsal["status"] != "awaiting_approval":
            raise ConflictError(f"预演当前状态为 {self._status_text(rehearsal['status'])}，不能重复确认")
        if not rehearsal["is_high_risk"]:
            raise ConflictError("低风险变更无需第二人确认，可直接应用")
        if principal.user_id == rehearsal["created_by"]:
            raise PermissionDeniedError("确认者不能是变更发起人，高风险变更须由另一位管理员确认")
        if decision not in {"approved", "rejected"}:
            raise ValidationError("确认结论只能是 approved 或 rejected")

        version = fingerprint_state(self.connection)
        now_text = to_storage(self.clock.now())
        self._record_decision(rehearsal_id, principal, decision, comment, version, now_text)
        new_status = "approved" if decision == "approved" else "rejected"
        self.connection.execute(
            "UPDATE role_change_rehearsals SET status=?,approved_by=?,approved_by_name=?,approved_at=?,"
            "approve_comment=? WHERE id=?",
            (new_status, principal.user_id, principal.display_name, now_text, comment, rehearsal_id),
        )
        self.audit.record(
            AuditContext(principal.user_id, principal.display_name),
            action="role.change.approve" if decision == "approved" else "role.change.reject",
            resource_type="role_change_rehearsal",
            resource_id=rehearsal_id,
            metadata={"role_code": rehearsal["role_code"], "state_version": version},
        )
        return self.detail(rehearsal_id)

    # ------------------------------------------------------------------ 应用

    def apply(self, principal: Principal, rehearsal_id: int) -> dict:
        principal.require("roles.write")
        rehearsal = self._require_rehearsal(rehearsal_id)
        if rehearsal["status"] == "applied":
            raise ConflictError("该预演已经应用，重复确认或重复应用都不会再次修改权限")
        if rehearsal["status"] == "awaiting_approval":
            raise ConflictError("高风险变更须先经第二位管理员确认后才能应用")
        if rehearsal["status"] == "rejected":
            raise ConflictError("预演已被拒绝，不能应用")
        self._ensure_fresh(rehearsal)
        if rehearsal["status"] != "approved":
            raise ConflictError(f"预演当前状态为 {self._status_text(rehearsal['status'])}，不能应用")

        role_id = rehearsal["role_id"]
        before_role = self._role_snapshot(role_id)
        base_codes = set(rehearsal["base_permissions"])
        requested_codes = rehearsal["requested_permissions"]
        # 以当前数据重算一次受影响用户与职责分离情况，用于和预演对账。
        current_impact = self._compute_impact(
            role=before_role,
            base_codes=base_codes,
            requested_codes=set(requested_codes),
            added=rehearsal["added_permissions"],
            removed=rehearsal["removed_permissions"],
        )

        now = self.clock.now()
        now_text = to_storage(now)

        if rehearsal["requested_name"] is not None:
            self.connection.execute(
                "UPDATE roles SET name=?,updated_at=? WHERE id=?",
                (rehearsal["requested_name"], now_text, role_id),
            )
        if rehearsal["requested_description"] is not None:
            self.connection.execute(
                "UPDATE roles SET description=?,updated_at=? WHERE id=?",
                (rehearsal["requested_description"], now_text, role_id),
            )
        permission_ids = self._resolve_permission_codes(requested_codes, as_ids=True)
        self.connection.execute("DELETE FROM role_permissions WHERE role_id=?", (role_id,))
        for permission_id in permission_ids:
            self.connection.execute(
                "INSERT INTO role_permissions(role_id,permission_id,granted_at) VALUES(?,?,?)",
                (role_id, permission_id, now_text),
            )

        # 只撤销实际能力发生变化的成员仍有效的会话。
        changed_user_ids = [item["user_id"] for item in current_impact["affected_users"]]
        revoked_session_rows: list[dict] = []
        if changed_user_ids:
            placeholders = ",".join("?" for _ in changed_user_ids)
            revoked_session_rows = rows_dict(self.connection.execute(
                f"SELECT id,user_id,client_label,issued_at,last_seen_at,expires_at FROM sessions "
                f"WHERE revoked_at IS NULL AND user_id IN ({placeholders}) ORDER BY id",
                tuple(changed_user_ids),
            ).fetchall())
            self.connection.execute(
                f"UPDATE sessions SET revoked_at=?,revoke_reason='role_permissions_changed' "
                f"WHERE revoked_at IS NULL AND user_id IN ({placeholders})",
                (now_text, *changed_user_ids),
            )

        after_role = self._role_snapshot(role_id)
        reconciliation = self._build_reconciliation(
            rehearsal=rehearsal,
            preview_impact=rehearsal["impact"],
            actual_impact=current_impact,
            revoked_sessions=revoked_session_rows,
        )
        applied_version = fingerprint_state(self.connection)
        self.connection.execute(
            "UPDATE role_change_rehearsals SET status='applied',applied_at=?,applied_state_version=?,"
            "reconciliation_json=? WHERE id=?",
            (now_text, applied_version,
             json.dumps(reconciliation, ensure_ascii=False, sort_keys=True), rehearsal_id),
        )

        self.audit.record(
            AuditContext(principal.user_id, principal.display_name),
            action="role.update",
            resource_type="role",
            resource_id=role_id,
            before=before_role,
            after=after_role,
            metadata={
                "rehearsal_id": rehearsal_id,
                "is_high_risk": rehearsal["is_high_risk"],
                "created_by": rehearsal["created_by_name"],
                "approved_by": rehearsal["approved_by_name"],
                "sessions_revoked": len(revoked_session_rows),
                "reconciliation": reconciliation,
            },
        )
        return self.detail(rehearsal_id)

    # -------------------------------------------------------------- 查询读取

    def list_rehearsals(self, principal: Principal, status: str | None = None) -> list[dict]:
        principal.require("roles.read")
        if status is not None and status not in {"awaiting_approval", "approved", "rejected", "applied", "expired"}:
            raise ValidationError("不支持的预演状态筛选")
        if status:
            rows = self.connection.execute(
                "SELECT * FROM role_change_rehearsals WHERE status=? ORDER BY id DESC LIMIT 100", (status,)
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM role_change_rehearsals ORDER BY id DESC LIMIT 100"
            ).fetchall()
        current_version = fingerprint_state(self.connection)
        return [self._serialize(row_dict(row), current_version=current_version) for row in rows]

    def detail(self, rehearsal_id: int) -> dict:
        return self._serialize(
            self._fetch_rehearsal_row(rehearsal_id),
            current_version=fingerprint_state(self.connection),
        )

    def get_detail(self, principal: Principal, rehearsal_id: int) -> dict:
        principal.require("roles.read")
        return self.detail(rehearsal_id)

    # -------------------------------------------------------------- 影响分析

    def _compute_impact(
        self,
        *,
        role: dict,
        base_codes: set[str],
        requested_codes: set[str],
        added: list[str],
        removed: list[str],
    ) -> dict[str, Any]:
        members = rows_dict(self.connection.execute(
            "SELECT u.id AS user_id,u.username,u.display_name,u.status,u.department_id,d.name AS department_name "
            "FROM users u JOIN user_roles ur ON ur.user_id=u.id "
            "LEFT JOIN departments d ON d.id=u.department_id WHERE ur.role_id=? ORDER BY u.id",
            (role["id"],),
        ).fetchall())

        # 除目标角色外，每个用户经由其它角色仍然拥有的权限（非成员即等于当前权限）。
        other_permissions: dict[int, set[str]] = defaultdict(set)
        for row in self.connection.execute(
            "SELECT DISTINCT ur.user_id,p.code FROM user_roles ur "
            "JOIN role_permissions rp ON rp.role_id=ur.role_id "
            "JOIN permissions p ON p.id=rp.permission_id WHERE ur.role_id!=?",
            (role["id"],),
        ).fetchall():
            other_permissions[int(row[0])].add(str(row[1]))

        affected_users: list[dict] = []
        before_map: dict[int, set[str]] = defaultdict(set)
        after_map: dict[int, set[str]] = defaultdict(set)
        all_users = rows_dict(self.connection.execute(
            "SELECT id,status,department_id FROM users"
        ).fetchall())
        for user in all_users:
            uid = int(user["id"])
            before_map[uid] = set(other_permissions[uid])
            after_map[uid] = set(other_permissions[uid])
        for member in members:
            uid = int(member["user_id"])
            before_map[uid] = other_permissions[uid] | base_codes
            after_map[uid] = other_permissions[uid] | requested_codes
            user_added = sorted(after_map[uid] - before_map[uid])
            user_removed = sorted(before_map[uid] - after_map[uid])
            if user_added or user_removed:
                affected_users.append({
                    "user_id": uid,
                    "username": member["username"],
                    "display_name": member["display_name"],
                    "status": member["status"],
                    "department_id": member["department_id"],
                    "department_name": member["department_name"],
                    "permissions_added": user_added,
                    "permissions_removed": user_removed,
                })

        changed_user_ids = {item["user_id"] for item in affected_users}
        active_sessions: list[dict] = []
        if changed_user_ids:
            placeholders = ",".join("?" for _ in changed_user_ids)
            now = self.clock.now()
            for row in self.connection.execute(
                f"SELECT s.id,s.user_id,u.username,s.client_label,s.issued_at,s.last_seen_at,s.expires_at "
                f"FROM sessions s JOIN users u ON u.id=s.user_id "
                f"WHERE s.revoked_at IS NULL AND s.user_id IN ({placeholders}) ORDER BY s.id",
                tuple(changed_user_ids),
            ).fetchall():
                expires_at = from_storage(row["expires_at"])
                active_sessions.append({
                    "session_id": int(row["id"]),
                    "user_id": int(row["user_id"]),
                    "username": row["username"],
                    "client_label": row["client_label"],
                    "issued_at": row["issued_at"],
                    "last_seen_at": row["last_seen_at"],
                    "expires_at": row["expires_at"],
                    "valid": expires_at is not None and expires_at > now,
                    "will_revoke": True,
                })

        affairs_map = self._open_business("affairs", OPEN_AFFAIR_STATUSES)
        petitions_map = self._open_business("petitions", OPEN_PETITION_STATUSES)
        business_maps = {"affairs.write": affairs_map, "petitions.write": petitions_map}

        # 受影响的待办类型：失去办理权限的成员所在部门仍有的在途业务。
        todo_index: dict[tuple[int, str], dict] = {}
        for item in affected_users:
            lost = set(item["permissions_removed"])
            department_id = item["department_id"]
            if department_id is None:
                continue
            for permission in TODO_PERMISSION_BUSINESS:
                if permission not in lost:
                    continue
                open_items = business_maps[permission].get(int(department_id))
                if not open_items:
                    continue
                key = (int(department_id), permission)
                entry = todo_index.get(key)
                if entry is None:
                    entry = {
                        "department_id": int(department_id),
                        "department_name": item["department_name"],
                        "business": TODO_PERMISSION_BUSINESS[permission],
                        "permission": permission,
                        "open_statuses": {status: len(ids) for status, ids in self._group_by_status(open_items).items()},
                        "open_item_ids": [open_item["id"] for open_item in open_items][:50],
                        "open_count": len(open_items),
                        "affected_user_ids": [],
                    }
                    todo_index[key] = entry
                if item["user_id"] not in entry["affected_user_ids"]:
                    entry["affected_user_ids"].append(item["user_id"])
        affected_todo_types = sorted(todo_index.values(), key=lambda value: (value["department_id"], value["permission"]))

        # 职责分离：变更前部门还有人能办、变更后无人可办的在途流程。
        user_records = {int(user["id"]): user for user in all_users}
        sod_blocked_flows = self._sod_blocked_flows(
            business_maps=business_maps,
            before_map=before_map,
            after_map=after_map,
            user_records=user_records,
        )

        return {
            "role": {"id": role["id"], "code": role["code"], "name": role["name"]},
            "permission_changes": {"added": added, "removed": removed},
            "affected_users": affected_users,
            "active_sessions": active_sessions,
            "affected_todo_types": affected_todo_types,
            "sod_blocked_flows": sod_blocked_flows,
            "summary": {
                "affected_user_count": len(affected_users),
                "session_count": len(active_sessions),
                "affected_todo_type_count": len(affected_todo_types),
                "blocked_flow_count": len(sod_blocked_flows),
            },
        }

    def _open_business(self, table: str, statuses: tuple[str, ...]) -> dict[int, list[dict]]:
        placeholders = ",".join("?" for _ in statuses)
        rows = self.connection.execute(
            f"SELECT id,status,department_id FROM {table} "
            f"WHERE status IN ({placeholders}) AND department_id IS NOT NULL ORDER BY id",
            statuses,
        ).fetchall()
        grouped: dict[int, list[dict]] = defaultdict(list)
        for row in rows:
            grouped[int(row["department_id"])].append({"id": int(row["id"]), "status": row["status"]})
        return grouped

    @staticmethod
    def _group_by_status(items: list[dict]) -> dict[str, list[int]]:
        grouped: dict[str, list[int]] = defaultdict(list)
        for item in items:
            grouped[item["status"]].append(item["id"])
        return grouped

    def _sod_blocked_flows(
        self,
        *,
        business_maps: dict[str, dict[int, list[dict]]],
        before_map: dict[int, set[str]],
        after_map: dict[int, set[str]],
        user_records: dict[int, dict],
    ) -> list[dict]:
        departments = {
            int(row["id"]): row["name"]
            for row in self.connection.execute("SELECT id,name FROM departments").fetchall()
        }
        blocked: list[dict] = []
        for permission, open_map in business_maps.items():
            for department_id, items in sorted(open_map.items()):
                before_handlers = self._department_handlers(department_id, permission, before_map, user_records)
                after_handlers = self._department_handlers(department_id, permission, after_map, user_records)
                if before_handlers and not after_handlers:
                    by_status = self._group_by_status(items)
                    blocked.append({
                        "department_id": department_id,
                        "department_name": departments.get(department_id),
                        "business": TODO_PERMISSION_BUSINESS[permission],
                        "permission": permission,
                        "open_statuses": {status: len(ids) for status, ids in by_status.items()},
                        "open_item_ids": [item["id"] for item in items][:50],
                        "open_count": len(items),
                        "previous_handler_ids": before_handlers,
                        "reason": f"变更后该部门没有任何在职用户具备 {permission}，在途{TODO_PERMISSION_BUSINESS[permission]}将无人能够继续办理",
                    })
        return blocked

    @staticmethod
    def _department_handlers(
        department_id: int,
        permission: str,
        perm_map: dict[int, set[str]],
        user_records: dict[int, dict],
    ) -> list[int]:
        handlers: list[int] = []
        for uid, perms in perm_map.items():
            user = user_records.get(uid)
            if user is None or user["status"] != "active":
                continue
            if "*" in perms or (user["department_id"] == department_id and permission in perms):
                handlers.append(uid)
        return sorted(handlers)

    # -------------------------------------------------------------- 对账记录

    def _build_reconciliation(
        self,
        *,
        rehearsal: dict,
        preview_impact: dict,
        actual_impact: dict,
        revoked_sessions: list[dict],
    ) -> dict[str, Any]:
        preview_users = {
            item["user_id"]: {
                "added": item["permissions_added"],
                "removed": item["permissions_removed"],
            }
            for item in preview_impact["affected_users"]
        }
        actual_users = {
            item["user_id"]: {
                "added": item["permissions_added"],
                "removed": item["permissions_removed"],
            }
            for item in actual_impact["affected_users"]
        }
        preview_blocked = sorted(
            (item["department_id"], item["permission"]) for item in preview_impact["sod_blocked_flows"]
        )
        actual_blocked = sorted(
            (item["department_id"], item["permission"]) for item in actual_impact["sod_blocked_flows"]
        )
        matches = (
            preview_users == actual_users
            and preview_impact["permission_changes"]["added"] == actual_impact["permission_changes"]["added"]
            and preview_impact["permission_changes"]["removed"] == actual_impact["permission_changes"]["removed"]
            and preview_blocked == actual_blocked
            and len(revoked_sessions) == preview_impact["summary"]["session_count"]
        )
        return {
            "matches_preview": matches,
            "permission_changes": {
                "preview": preview_impact["permission_changes"],
                "actual": actual_impact["permission_changes"],
            },
            "users": {
                "preview_affected_user_ids": sorted(preview_users),
                "actual_affected_user_ids": sorted(actual_users),
                "actual_changes": [
                    {"user_id": uid, **change} for uid, change in sorted(actual_users.items())
                ],
            },
            "sod_blocked_flows": {
                "preview": [
                    {"department_id": dept, "permission": permission} for dept, permission in preview_blocked
                ],
                "actual": [
                    {"department_id": dept, "permission": permission} for dept, permission in actual_blocked
                ],
            },
            "sessions": {
                "preview_active_count": preview_impact["summary"]["session_count"],
                "actually_revoked_count": len(revoked_sessions),
                "revoked_session_ids": [int(row["id"]) for row in revoked_sessions],
            },
            "approval": {
                "created_by": rehearsal["created_by_name"],
                "approved_by": rehearsal["approved_by_name"],
                "approved_at": rehearsal["approved_at"],
            },
        }

    # -------------------------------------------------------------- 辅助方法

    def _ensure_fresh(self, rehearsal: dict) -> None:
        expires_at = from_storage(rehearsal["expires_at"])
        if expires_at is not None and expires_at <= self.clock.now():
            raise ConflictError("预演已超过有效期，请重新预演")
        current_version = fingerprint_state(self.connection)
        if current_version != rehearsal["state_version"]:
            raise ConflictError(
                "自预演生成以来用户角色、权限或在途业务状态已经变化，旧预演结果禁止使用，请重新预演",
                context={"expected_version": rehearsal["state_version"], "current_version": current_version},
            )

    def _record_decision(
        self,
        rehearsal_id: int,
        principal: Principal,
        decision: str,
        comment: str,
        version: str,
        now_text: str,
    ) -> None:
        try:
            self.connection.execute(
                "INSERT INTO role_change_approvals(rehearsal_id,approver_user_id,approver_name,decision,"
                "comment,state_version_at_decision,created_at) VALUES(?,?,?,?,?,?,?)",
                (rehearsal_id, principal.user_id, principal.display_name, decision, comment, version, now_text),
            )
        except sqlite3.IntegrityError:
            raise ConflictError("同一管理员不能对同一预演重复确认") from None

    def _require_role(self, role_id: int) -> dict:
        role = row_dict(self.connection.execute("SELECT * FROM roles WHERE id=?", (role_id,)).fetchone())
        if role is None:
            raise NotFoundError("角色不存在")
        return role

    def resolve_role_id(self, role_ref: str) -> int:
        """接受角色数字 ID 或角色编码。"""
        if role_ref.isdigit():
            row = self.connection.execute("SELECT id FROM roles WHERE id=?", (int(role_ref),)).fetchone()
            if row is not None:
                return int(row[0])
        row = self.connection.execute("SELECT id FROM roles WHERE code=?", (role_ref,)).fetchone()
        if row is None:
            raise NotFoundError(f"角色不存在：{role_ref}")
        return int(row[0])

    def _require_rehearsal(self, rehearsal_id: int) -> dict:
        return self._serialize(
            self._fetch_rehearsal_row(rehearsal_id),
            current_version=fingerprint_state(self.connection),
        )

    def _fetch_rehearsal_row(self, rehearsal_id: int) -> dict:
        row = row_dict(self.connection.execute(
            "SELECT * FROM role_change_rehearsals WHERE id=?", (rehearsal_id,)
        ).fetchone())
        if row is None:
            raise NotFoundError("角色变更预演不存在")
        return row

    def _role_permission_codes(self, role_id: int) -> list[str]:
        rows = self.connection.execute(
            "SELECT p.code FROM permissions p JOIN role_permissions rp ON rp.permission_id=p.id "
            "WHERE rp.role_id=? ORDER BY p.code",
            (role_id,),
        ).fetchall()
        return [str(row[0]) for row in rows]

    def _resolve_permission_codes(self, codes: list[str], *, as_ids: bool = False) -> list[str] | list[int]:
        result: list[str] | list[int] = []
        for code in dict.fromkeys(codes):
            row = self.connection.execute("SELECT id FROM permissions WHERE code=?", (code,)).fetchone()
            if row is None:
                raise NotFoundError(f"权限不存在：{code}")
            result.append(int(row[0]) if as_ids else str(code))
        return result

    def _role_snapshot(self, role_id: int) -> dict:
        role = self._require_role(role_id)
        role["permissions"] = self._role_permission_codes(role_id)
        return role

    @staticmethod
    def _status_text(status: str) -> str:
        return {
            "awaiting_approval": "待确认",
            "approved": "已确认",
            "rejected": "已拒绝",
            "applied": "已应用",
            "expired": "已失效",
        }.get(status, status)

    def _serialize(self, row: dict, *, current_version: str | None = None) -> dict:
        def load(key: str, default: Any) -> Any:
            value = row.get(key)
            return json.loads(value) if value is not None else default

        status = row["status"]
        # 对尚未终结的预演，在读取时惰性判定是否已失效：超期或数据版本已变化。
        # 这里只反映状态，不做写入；真正的拒绝逻辑在 _ensure_fresh 中。
        if status in {"awaiting_approval", "approved"}:
            expires_at = from_storage(row["expires_at"])
            expired = expires_at is not None and expires_at <= self.clock.now()
            if not expired and current_version is not None and current_version != row["state_version"]:
                expired = True
            if expired:
                status = "expired"
        approvals = rows_dict(self.connection.execute(
            "SELECT approver_user_id,approver_name,decision,comment,state_version_at_decision,created_at "
            "FROM role_change_approvals WHERE rehearsal_id=? ORDER BY id",
            (row["id"],),
        ).fetchall())
        return {
            "id": row["id"],
            "role_id": row["role_id"],
            "role_code": row["role_code"],
            "requested_name": row["requested_name"],
            "requested_description": row["requested_description"],
            "base_permissions": load("base_permissions_json", []),
            "requested_permissions": load("requested_permissions_json", []),
            "added_permissions": load("added_permissions_json", []),
            "removed_permissions": load("removed_permissions_json", []),
            "is_high_risk": bool(row["is_high_risk"]),
            "status": status,
            "status_text": self._status_text(status),
            "impact": load("impact_json", {}),
            "state_version": row["state_version"],
            "state_snapshot": load("state_snapshot_json", {}),
            "created_by": row["created_by"],
            "created_by_name": row["created_by_name"],
            "request_comment": row["request_comment"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "approved_by": row["approved_by"],
            "approved_by_name": row["approved_by_name"],
            "approved_at": row["approved_at"],
            "approve_comment": row["approve_comment"],
            "approvals": approvals,
            "applied_at": row["applied_at"],
            "applied_state_version": row["applied_state_version"],
            "reconciliation": load("reconciliation_json", None),
        }
