from __future__ import annotations

import json
import sqlite3

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, NotFoundError
from app.core.security import Principal, request_fingerprint
from app.repositories.base import rows_dict
from app.repositories.identity import RoleRepository
from app.services.audit import AuditContext, AuditService

IN_FLIGHT_AFFAIR_STATUSES = ("待受理", "办理中", "已退回")
IN_FLIGHT_PETITION_STATUSES = ("待签收", "待分派", "办理中", "待审核", "退回重办", "复查中")

# 数据版本指纹覆盖的表与字段：只纳入会影响预演结论的列，
# 会话的 last_seen_at、用户的 updated_at 等易变但不影响结论的字段不纳入。
STATE_QUERIES = {
    "users": "SELECT id,status,department_id FROM users ORDER BY id",
    "user_roles": "SELECT user_id,role_id FROM user_roles ORDER BY user_id,role_id",
    "role_permissions": "SELECT role_id,permission_id FROM role_permissions ORDER BY role_id,permission_id",
    "permissions": "SELECT id,code FROM permissions ORDER BY id",
    "sessions": "SELECT id,user_id,expires_at,revoked_at FROM sessions ORDER BY id",
    "affairs": "SELECT id,status,department_id FROM affairs ORDER BY id",
    "petitions": "SELECT id,status,department_id FROM petitions ORDER BY id",
    "petition_flow_records": "SELECT id,petition_id,action,operator FROM petition_flow_records ORDER BY id",
}

OPEN_STATUSES = ("pending", "confirmed")


class RoleChangeService:
    """角色权限变更的影响预演、双人确认与应用对账。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.roles = RoleRepository(connection)
        self.audit = AuditService(connection, self.clock)

    # ------------------------------------------------------------------
    # 预演生成与查询
    # ------------------------------------------------------------------

    def create_preview(self, principal: Principal, role_id: int, permission_codes: list[str]) -> dict:
        principal.require("roles.write")
        role = self.roles.require(role_id)
        proposed = self._resolve_permission_codes(permission_codes)
        impact = self._compute_impact(role_id, proposed)
        fingerprint = self._state_fingerprint()
        change = {"permission_codes": sorted(proposed)}
        now = to_storage(self.clock.now())
        cursor = self.connection.execute(
            "INSERT INTO role_change_previews(role_id,change_json,impact_json,base_fingerprint,risk_level,status,"
            "created_by,created_by_name,created_at,updated_at) VALUES(?,?,?,?,?,'pending',?,?,?,?)",
            (
                role_id,
                json.dumps(change, ensure_ascii=False, sort_keys=True),
                json.dumps(impact, ensure_ascii=False, sort_keys=True),
                fingerprint,
                impact["risk_level"],
                principal.user_id,
                principal.display_name,
                now,
                now,
            ),
        )
        preview_id = int(cursor.lastrowid)
        self.audit.record(
            AuditContext(principal.user_id, principal.display_name),
            action="role_change.preview",
            resource_type="role_change_preview",
            resource_id=preview_id,
            after={"role_id": role_id, "change": change, "risk_level": impact["risk_level"]},
            metadata={"role_code": role["code"], "summary": impact["summary"]},
        )
        return self._serialize(self._require(preview_id))

    def list_for_role(self, principal: Principal, role_id: int) -> list[dict]:
        principal.require("roles.read")
        self.roles.require(role_id)
        rows = rows_dict(
            self.connection.execute(
                "SELECT * FROM role_change_previews WHERE role_id=? ORDER BY id DESC", (role_id,)
            ).fetchall()
        )
        return [self._serialize(self._refresh_stale(row), details=False) for row in rows]

    def get_preview(self, principal: Principal, preview_id: int) -> dict:
        principal.require("roles.read")
        return self._serialize(self._refresh_stale(self._require(preview_id)))

    # ------------------------------------------------------------------
    # 确认、应用、取消
    # ------------------------------------------------------------------

    def confirm(self, principal: Principal, preview_id: int) -> dict:
        principal.require("roles.write")
        preview = self._require(preview_id)
        if preview["status"] == "confirmed":
            return self._serialize(preview)  # 幂等：重复确认不产生额外效果
        if preview["status"] != "pending":
            raise ConflictError(f"预演单当前状态为 {preview['status']}，不能确认")
        if int(preview["created_by"]) == principal.user_id:
            raise ConflictError("确认者不能是预演发起人")
        self._ensure_fresh(preview)
        now = to_storage(self.clock.now())
        cursor = self.connection.execute(
            "UPDATE role_change_previews SET status='confirmed',confirmed_by=?,confirmed_by_name=?,"
            "confirmed_at=?,updated_at=? WHERE id=? AND status='pending'",
            (principal.user_id, principal.display_name, now, now, preview_id),
        )
        if cursor.rowcount != 1:
            raise ConflictError("预演单状态已变化，请刷新后重试")
        self.audit.record(
            AuditContext(principal.user_id, principal.display_name),
            action="role_change.confirm",
            resource_type="role_change_preview",
            resource_id=preview_id,
            metadata={"role_id": preview["role_id"], "risk_level": preview["risk_level"]},
        )
        return self._serialize(self._require(preview_id))

    def apply(self, principal: Principal, preview_id: int) -> dict:
        principal.require("roles.write")
        preview = self._require(preview_id)
        if preview["status"] == "applied":
            return self._serialize(preview)  # 幂等：重复应用不再次修改权限
        if preview["status"] in {"stale", "cancelled"}:
            raise ConflictError(f"预演单当前状态为 {preview['status']}，不能应用")
        self._ensure_fresh(preview)
        if preview["risk_level"] == "high" and preview["status"] != "confirmed":
            raise ConflictError("高风险变更需要第二位管理员确认后才能应用")

        role_id = int(preview["role_id"])
        role = self.roles.require(role_id)
        proposed = set(json.loads(preview["change_json"])["permission_codes"])
        before_permissions = sorted(item["code"] for item in self.roles.permissions(role_id))
        # 应用时刻重新计算影响，作为对账的实际侧
        impact_now = self._compute_impact(role_id, proposed)
        now = to_storage(self.clock.now())

        permission_ids = self._permission_ids(proposed)
        self.connection.execute("DELETE FROM role_permissions WHERE role_id=?", (role_id,))
        for permission_id in permission_ids:
            self.connection.execute(
                "INSERT INTO role_permissions(role_id,permission_id,granted_at) VALUES(?,?,?)",
                (role_id, permission_id, now),
            )
        self.connection.execute("UPDATE roles SET updated_at=? WHERE id=?", (now, role_id))

        revoked_sessions = self._revoke_affected_sessions(impact_now, now)

        reconciliation = self._reconciliation(preview, impact_now, before_permissions, revoked_sessions, principal, now)
        cursor = self.connection.execute(
            "UPDATE role_change_previews SET status='applied',applied_by=?,applied_by_name=?,applied_at=?,"
            "reconciliation_json=?,updated_at=? WHERE id=? AND status IN ('pending','confirmed')",
            (
                principal.user_id,
                principal.display_name,
                now,
                json.dumps(reconciliation, ensure_ascii=False, sort_keys=True),
                now,
                preview_id,
            ),
        )
        if cursor.rowcount != 1:
            raise ConflictError("预演单状态已变化，请刷新后重试")
        self.audit.record(
            AuditContext(principal.user_id, principal.display_name),
            action="role_change.apply",
            resource_type="role",
            resource_id=role_id,
            before={"permissions": before_permissions},
            after={"permissions": sorted(proposed)},
            metadata={
                "preview_id": preview_id,
                "role_code": role["code"],
                "risk_level": preview["risk_level"],
                "revoked_session_count": len(revoked_sessions),
                "matches_preview": reconciliation["actual"]["matches_preview"],
            },
        )
        return self._serialize(self._require(preview_id))

    def cancel(self, principal: Principal, preview_id: int) -> dict:
        principal.require("roles.write")
        preview = self._require(preview_id)
        if preview["status"] == "cancelled":
            return self._serialize(preview)
        if preview["status"] not in OPEN_STATUSES:
            raise ConflictError(f"预演单当前状态为 {preview['status']}，不能取消")
        now = to_storage(self.clock.now())
        self.connection.execute(
            "UPDATE role_change_previews SET status='cancelled',updated_at=? WHERE id=?",
            (now, preview_id),
        )
        self.audit.record(
            AuditContext(principal.user_id, principal.display_name),
            action="role_change.cancel",
            resource_type="role_change_preview",
            resource_id=preview_id,
            metadata={"role_id": preview["role_id"]},
        )
        return self._serialize(self._require(preview_id))

    # ------------------------------------------------------------------
    # 数据版本
    # ------------------------------------------------------------------

    def check_freshness(self, principal: Principal, preview_id: int) -> None:
        """在自动提交模式下校验数据版本，让失效标记与审计在报错前落库。"""
        principal.require("roles.write")
        preview = self._require(preview_id)
        if preview["status"] in OPEN_STATUSES:
            self._ensure_fresh(preview)

    def _state_fingerprint(self) -> str:
        payload = {
            name: [list(row) for row in self.connection.execute(query).fetchall()]
            for name, query in STATE_QUERIES.items()
        }
        return request_fingerprint(payload)

    def _ensure_fresh(self, preview: dict) -> None:
        if self._state_fingerprint() == preview["base_fingerprint"]:
            return
        now = to_storage(self.clock.now())
        self.connection.execute(
            "UPDATE role_change_previews SET status='stale',updated_at=? WHERE id=? AND status IN ('pending','confirmed')",
            (now, preview["id"]),
        )
        self.audit.record(
            AuditContext(int(preview["created_by"]), str(preview["created_by_name"])),
            action="role_change.stale",
            resource_type="role_change_preview",
            resource_id=preview["id"],
            outcome="failure",
            metadata={"role_id": preview["role_id"], "base_fingerprint": preview["base_fingerprint"]},
        )
        raise ConflictError("预演基于的数据版本已变化，预演单已作废，请重新生成预演")

    def _refresh_stale(self, preview: dict) -> dict:
        if preview["status"] in OPEN_STATUSES and self._state_fingerprint() != preview["base_fingerprint"]:
            now = to_storage(self.clock.now())
            self.connection.execute(
                "UPDATE role_change_previews SET status='stale',updated_at=? WHERE id=? AND status IN ('pending','confirmed')",
                (now, preview["id"]),
            )
            refreshed = self._require(int(preview["id"]))
            return refreshed if refreshed["status"] == "stale" else preview
        return preview

    # ------------------------------------------------------------------
    # 影响分析
    # ------------------------------------------------------------------

    def _compute_impact(self, role_id: int, proposed: set[str]) -> dict:
        now = to_storage(self.clock.now())
        permission_rows = rows_dict(self.connection.execute("SELECT id,code FROM permissions ORDER BY code").fetchall())
        id_to_code = {int(row["id"]): str(row["code"]) for row in permission_rows}
        role_permissions: dict[int, set[str]] = {}
        for row in self.connection.execute("SELECT role_id,permission_id FROM role_permissions").fetchall():
            role_permissions.setdefault(int(row[0]), set()).add(id_to_code[int(row[1])])
        current = set(role_permissions.get(role_id, set()))

        user_rows = rows_dict(
            self.connection.execute(
                "SELECT id,username,display_name,department_id,status FROM users ORDER BY id"
            ).fetchall()
        )
        user_role_ids: dict[int, set[int]] = {}
        for row in self.connection.execute("SELECT user_id,role_id FROM user_roles").fetchall():
            user_role_ids.setdefault(int(row[0]), set()).add(int(row[1]))

        def effective(user_id: int, after: bool) -> set[str]:
            granted: set[str] = set()
            for owned_role_id in user_role_ids.get(user_id, set()):
                if after and owned_role_id == role_id:
                    granted |= proposed
                else:
                    granted |= role_permissions.get(owned_role_id, set())
            return granted

        before_map = {int(user["id"]): effective(int(user["id"]), after=False) for user in user_rows}
        after_map = {int(user["id"]): effective(int(user["id"]), after=True) for user in user_rows}

        affected_users = []
        for user in user_rows:
            user_id = int(user["id"])
            if role_id not in user_role_ids.get(user_id, set()):
                continue
            lost = sorted(before_map[user_id] - after_map[user_id])
            gained = sorted(after_map[user_id] - before_map[user_id])
            if lost or gained:
                affected_users.append(
                    {
                        "user_id": user_id,
                        "username": user["username"],
                        "display_name": user["display_name"],
                        "department_id": user["department_id"],
                        "status": user["status"],
                        "lost_permissions": lost,
                        "gained_permissions": gained,
                    }
                )

        active_sessions = self._active_sessions([item["user_id"] for item in affected_users], now)

        def eligible_ids(permission: str, department_id: int | None, permission_map: dict[int, set[str]]) -> list[int]:
            eligible: list[int] = []
            for user in user_rows:
                if user["status"] != "active":
                    continue
                granted = permission_map[int(user["id"])]
                if "*" in granted:
                    eligible.append(int(user["id"]))
                elif permission in granted and (department_id is None or user["department_id"] == department_id):
                    eligible.append(int(user["id"]))
            return eligible

        affair_statuses = ",".join(f"'{status}'" for status in IN_FLIGHT_AFFAIR_STATUSES)
        petition_statuses = ",".join(f"'{status}'" for status in IN_FLIGHT_PETITION_STATUSES)
        affair_rows = rows_dict(
            self.connection.execute(
                "SELECT a.id,a.category AS item_type,a.status,a.department_id,d.name AS department_name "
                "FROM affairs a LEFT JOIN departments d ON d.id=a.department_id "
                f"WHERE a.status IN ({affair_statuses}) ORDER BY a.id"
            ).fetchall()
        )
        petition_rows = rows_dict(
            self.connection.execute(
                "SELECT p.id,p.type AS item_type,p.status,p.department_id,d.name AS department_name "
                "FROM petitions p LEFT JOIN departments d ON d.id=p.department_id "
                f"WHERE p.status IN ({petition_statuses}) ORDER BY p.id"
            ).fetchall()
        )
        todo_impacts = self._todo_impacts(affair_rows, "affair", "affairs.write", eligible_ids, before_map, after_map)
        todo_impacts += self._todo_impacts(petition_rows, "petition", "petitions.write", eligible_ids, before_map, after_map)
        sod_blocked = self._sod_blocked(petition_rows, user_rows, eligible_ids, after_map)

        users_losing = [item for item in affected_users if item["lost_permissions"]]
        users_gaining = [item for item in affected_users if item["gained_permissions"]]
        blocked_todo = sum(group["blocked"] for group in todo_impacts)
        risk_level = "high" if (users_losing or blocked_todo or sod_blocked) else "low"
        return {
            "generated_at": now,
            "role_id": role_id,
            "permission_changes": {
                "added": sorted(proposed - current),
                "removed": sorted(current - proposed),
            },
            "affected_users": affected_users,
            "active_sessions": active_sessions,
            "todo_impacts": todo_impacts,
            "sod_blocked": sod_blocked,
            "risk_level": risk_level,
            "summary": {
                "affected_user_count": len(affected_users),
                "users_losing_count": len(users_losing),
                "users_gaining_count": len(users_gaining),
                "active_session_count": len(active_sessions),
                "affected_todo_count": sum(group["affected"] for group in todo_impacts),
                "blocked_todo_count": blocked_todo,
                "sod_blocked_count": len(sod_blocked),
            },
        }

    def _active_sessions(self, user_ids: list[int], now: str) -> list[dict]:
        if not user_ids:
            return []
        placeholders = ",".join("?" for _ in user_ids)
        return rows_dict(
            self.connection.execute(
                "SELECT s.id AS session_id,s.user_id,u.username,u.display_name,s.client_label,s.issued_at,s.expires_at "
                f"FROM sessions s JOIN users u ON u.id=s.user_id "
                f"WHERE s.revoked_at IS NULL AND s.expires_at>? AND s.user_id IN ({placeholders}) ORDER BY s.id",
                (now, *user_ids),
            ).fetchall()
        )

    def _todo_impacts(self, rows, kind, permission, eligible_ids, before_map, after_map) -> list[dict]:
        groups: dict[tuple, dict] = {}
        for row in rows:
            key = (row["item_type"], row["department_id"])
            group = groups.setdefault(
                key,
                {
                    "kind": kind,
                    "type": row["item_type"],
                    "department_id": row["department_id"],
                    "department_name": row["department_name"],
                    "in_flight": 0,
                    "affected": 0,
                    "blocked": 0,
                    "sample_item_ids": [],
                },
            )
            group["in_flight"] += 1
            before_count = len(eligible_ids(permission, row["department_id"], before_map))
            after_count = len(eligible_ids(permission, row["department_id"], after_map))
            if after_count < before_count:
                group["affected"] += 1
                if len(group["sample_item_ids"]) < 5:
                    group["sample_item_ids"].append(int(row["id"]))
                if after_count == 0:
                    group["blocked"] += 1
        return [group for group in groups.values() if group["affected"] or group["blocked"]]

    def _sod_blocked(self, petition_rows, user_rows, eligible_ids, after_map) -> list[dict]:
        """职责分离：信访相邻两个流转动作不得由同一人完成。

        若变更后具备 petitions.write 的合格办理人只剩下上一步操作人，
        该流程将因无人可合规接手而无法继续。
        """
        blocked = []
        for row in petition_rows:
            eligible_after = eligible_ids("petitions.write", row["department_id"], after_map)
            if not eligible_after:
                continue  # 已计入待办 blocked，不重复计入职责分离
            last = self.connection.execute(
                "SELECT operator FROM petition_flow_records WHERE petition_id=? AND operator IS NOT NULL ORDER BY id DESC LIMIT 1",
                (row["id"],),
            ).fetchone()
            if last is None:
                continue
            excluded = {int(user["id"]) for user in user_rows if user["display_name"] == last[0]}
            if not excluded:
                continue
            remaining = [user_id for user_id in eligible_after if user_id not in excluded]
            if not remaining:
                blocked.append(
                    {
                        "petition_id": int(row["id"]),
                        "type": row["item_type"],
                        "status": row["status"],
                        "department_id": row["department_id"],
                        "department_name": row["department_name"],
                        "last_operator": last[0],
                        "eligible_user_ids_after": eligible_after,
                    }
                )
        return blocked

    # ------------------------------------------------------------------
    # 应用辅助
    # ------------------------------------------------------------------

    def _revoke_affected_sessions(self, impact_now: dict, now: str) -> list[dict]:
        revoked = []
        for session in impact_now["active_sessions"]:
            cursor = self.connection.execute(
                "UPDATE sessions SET revoked_at=?,revoke_reason='role_permissions_changed' WHERE id=? AND revoked_at IS NULL",
                (now, session["session_id"]),
            )
            if cursor.rowcount == 1:
                revoked.append(
                    {
                        "session_id": session["session_id"],
                        "user_id": session["user_id"],
                        "username": session["username"],
                        "client_label": session["client_label"],
                    }
                )
        return revoked

    def _reconciliation(self, preview, impact_now, before_permissions, revoked_sessions, principal, now) -> dict:
        preview_impact = json.loads(preview["impact_json"])
        proposed = sorted(json.loads(preview["change_json"])["permission_codes"])

        def user_snapshot(users) -> list:
            return sorted(
                (item["user_id"], tuple(item["lost_permissions"]), tuple(item["gained_permissions"]))
                for item in users
            )

        matches = user_snapshot(preview_impact["affected_users"]) == user_snapshot(impact_now["affected_users"])
        return {
            "preview": {
                "generated_at": preview_impact["generated_at"],
                "base_fingerprint": preview["base_fingerprint"],
                "summary": preview_impact["summary"],
                "affected_users": preview_impact["affected_users"],
            },
            "approval": {
                "required": preview["risk_level"] == "high",
                "confirmed_by": preview["confirmed_by"],
                "confirmed_by_name": preview["confirmed_by_name"],
                "confirmed_at": preview["confirmed_at"],
            },
            "actual": {
                "applied_by": principal.user_id,
                "applied_by_name": principal.display_name,
                "applied_at": now,
                "role_permissions_before": before_permissions,
                "role_permissions_after": proposed,
                "affected_users": impact_now["affected_users"],
                "revoked_sessions": revoked_sessions,
                "matches_preview": matches,
            },
        }

    # ------------------------------------------------------------------
    # 基础工具
    # ------------------------------------------------------------------

    def _require(self, preview_id: int) -> dict:
        row = self.connection.execute("SELECT * FROM role_change_previews WHERE id=?", (preview_id,)).fetchone()
        if row is None:
            raise NotFoundError("预演单不存在")
        return dict(row)

    def _serialize(self, row: dict, *, details: bool = True) -> dict:
        result = dict(row)
        result["change"] = json.loads(result.pop("change_json"))
        impact = json.loads(result.pop("impact_json"))
        reconciliation = result.pop("reconciliation_json")
        result["summary"] = impact["summary"]
        if details:
            result["impact"] = impact
            result["reconciliation"] = json.loads(reconciliation) if reconciliation else None
        return result

    def _resolve_permission_codes(self, codes: list[str]) -> set[str]:
        proposed: set[str] = set()
        for code in dict.fromkeys(codes):
            row = self.connection.execute("SELECT id FROM permissions WHERE code=?", (code,)).fetchone()
            if row is None:
                raise NotFoundError(f"权限不存在：{code}")
            proposed.add(str(code))
        return proposed

    def _permission_ids(self, codes: set[str]) -> list[int]:
        if not codes:
            return []
        placeholders = ",".join("?" for _ in codes)
        rows = self.connection.execute(
            f"SELECT id FROM permissions WHERE code IN ({placeholders}) ORDER BY code", tuple(sorted(codes))
        ).fetchall()
        return [int(row[0]) for row in rows]
