from __future__ import annotations

import pytest

from app.database import get_connection


def create_user(client, admin, username, display_name, role_codes, department_id=None):
    response = client.post(
        "/api/users",
        headers=admin["headers"],
        json={
            "username": username,
            "password": "Clerk!23456",
            "display_name": display_name,
            "role_codes": role_codes,
            "department_id": department_id,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def login(client, username, password="Clerk!23456"):
    response = client.post("/api/auth/login", json={"username": username, "password": password, "client_label": "tests"})
    assert response.status_code == 200, response.text
    token = response.json()["token"]
    return {"token": token, "headers": {"Authorization": f"Bearer {token}"}}


@pytest.fixture()
def second_admin(client, admin):
    create_user(client, admin, "admin.two", "管理员乙", ["administrator"])
    return login(client, "admin.two")


@pytest.fixture()
def department(client, admin):
    response = client.post(
        "/api/departments",
        headers=admin["headers"],
        json={"name": "民政服务所", "manager": "王所长", "phone": "0571-88888888"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def seed_in_flight_business(department_id: int) -> dict:
    """直接写入在途业务数据：一件低保事务、一件待审核投诉信访（含流转记录）。"""
    connection = get_connection()
    cursor = connection.execute(
        "INSERT INTO residents(name,id_card,gender,birth_date,address,village) VALUES('张大爷','330106195001010011','男','1950-01-01','幸福路1号','幸福村')"
    )
    resident_id = int(cursor.lastrowid)
    cursor = connection.execute(
        "INSERT INTO affairs(title,category,applicant_id,status,department_id) VALUES('低保申请','低保',?,'办理中',?)",
        (resident_id, department_id),
    )
    affair_id = int(cursor.lastrowid)
    cursor = connection.execute(
        "INSERT INTO petitions(type,target,content,status,department_id) VALUES('投诉举报','村委会','反映问题','待审核',?)",
        (department_id,),
    )
    petition_id = int(cursor.lastrowid)
    return {"resident_id": resident_id, "affair_id": affair_id, "petition_id": petition_id}


def append_flow(petition_id: int, action: str, operator: str) -> None:
    get_connection().execute(
        "INSERT INTO petition_flow_records(petition_id,action,operator) VALUES(?,?,?)",
        (petition_id, action, operator),
    )


def role_permissions(client, admin, role_id: int) -> list[str]:
    response = client.get(f"/api/roles/{role_id}", headers=admin["headers"])
    assert response.status_code == 200
    return sorted(item["code"] for item in response.json()["permissions"])


def test_high_risk_preview_confirm_apply_and_idempotency(client, admin, second_admin, department):
    role = client.post(
        "/api/roles",
        headers=admin["headers"],
        json={"code": "case.handler", "name": "事项办理员", "permission_codes": ["affairs.read", "affairs.write", "petitions.write"]},
    ).json()
    clerk = create_user(client, admin, "clerk.zhang", "张经办", ["case.handler"], department_id=department["id"])
    clerk_session = login(client, "clerk.zhang")
    business = seed_in_flight_business(department["id"])

    # 生成预演：去掉 affairs.write 与 petitions.write
    preview = client.post(
        f"/api/roles/{role['id']}/change-previews",
        headers=admin["headers"],
        json={"permission_codes": ["affairs.read"]},
    )
    assert preview.status_code == 201, preview.text
    body = preview.json()
    assert body["status"] == "pending"
    assert body["risk_level"] == "high"
    assert body["base_fingerprint"]
    impact = body["impact"]
    assert impact["permission_changes"]["removed"] == ["affairs.write", "petitions.write"]
    assert impact["affected_users"][0]["username"] == "clerk.zhang"
    assert impact["affected_users"][0]["lost_permissions"] == ["affairs.write", "petitions.write"]
    assert len(impact["active_sessions"]) == 1
    assert impact["active_sessions"][0]["username"] == "clerk.zhang"
    kinds = {(item["kind"], item["type"]) for item in impact["todo_impacts"]}
    assert ("affair", "低保") in kinds
    assert ("petition", "投诉举报") in kinds
    assert impact["summary"]["blocked_todo_count"] == 2
    preview_id = body["id"]

    # 高风险未确认直接应用 → 409
    denied = client.post(f"/api/role-change-previews/{preview_id}/apply", headers=admin["headers"])
    assert denied.status_code == 409

    # 发起人不能自己确认 → 409
    self_confirm = client.post(f"/api/role-change-previews/{preview_id}/confirm", headers=admin["headers"])
    assert self_confirm.status_code == 409

    # 第二位管理员确认 → 200
    confirmed = client.post(f"/api/role-change-previews/{preview_id}/confirm", headers=second_admin["headers"])
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json()["status"] == "confirmed"
    assert confirmed.json()["confirmed_by_name"] == "管理员乙"

    # 重复确认幂等，不产生额外效果
    reconfirmed = client.post(f"/api/role-change-previews/{preview_id}/confirm", headers=second_admin["headers"])
    assert reconfirmed.status_code == 200
    assert reconfirmed.json()["status"] == "confirmed"

    # 应用 → 权限替换、会话撤销、对账记录
    applied = client.post(f"/api/role-change-previews/{preview_id}/apply", headers=admin["headers"])
    assert applied.status_code == 200, applied.text
    result = applied.json()
    assert result["status"] == "applied"
    assert role_permissions(client, admin, role["id"]) == ["affairs.read"]

    reconciliation = result["reconciliation"]
    assert reconciliation["approval"]["required"] is True
    assert reconciliation["approval"]["confirmed_by_name"] == "管理员乙"
    assert reconciliation["actual"]["role_permissions_before"] == ["affairs.read", "affairs.write", "petitions.write"]
    assert reconciliation["actual"]["role_permissions_after"] == ["affairs.read"]
    assert reconciliation["actual"]["matches_preview"] is True
    assert len(reconciliation["actual"]["revoked_sessions"]) == 1
    assert reconciliation["preview"]["summary"]["blocked_todo_count"] == 2

    # 受影响用户的旧会话已被撤销
    me = client.get("/api/auth/me", headers=clerk_session["headers"])
    assert me.status_code == 401

    # 重复应用幂等：返回既有对账，权限不被再次修改
    reapplied = client.post(f"/api/role-change-previews/{preview_id}/apply", headers=admin["headers"])
    assert reapplied.status_code == 200
    assert reapplied.json()["reconciliation"]["actual"]["applied_at"] == reconciliation["actual"]["applied_at"]
    assert role_permissions(client, admin, role["id"]) == ["affairs.read"]
    events = client.get("/api/audit?action=role_change.apply", headers=admin["headers"]).json()
    assert events["total"] == 1


def test_stale_preview_is_rejected(client, admin, second_admin, department):
    role = client.post(
        "/api/roles",
        headers=admin["headers"],
        json={"code": "case.handler", "name": "事项办理员", "permission_codes": ["affairs.write"]},
    ).json()
    create_user(client, admin, "clerk.zhang", "张经办", ["case.handler"], department_id=department["id"])
    preview = client.post(
        f"/api/roles/{role['id']}/change-previews",
        headers=admin["headers"],
        json={"permission_codes": []},
    ).json()
    preview_id = preview["id"]

    # 预演生成后业务状态变化：新增一件在途事务
    seed_in_flight_business(department["id"])

    applied = client.post(f"/api/role-change-previews/{preview_id}/apply", headers=admin["headers"])
    assert applied.status_code == 409
    assert "已变化" in applied.json()["error"]["message"]

    detail = client.get(f"/api/role-change-previews/{preview_id}", headers=admin["headers"])
    assert detail.json()["status"] == "stale"

    # 已作废的预演不能再确认或应用
    confirm = client.post(f"/api/role-change-previews/{preview_id}/confirm", headers=second_admin["headers"])
    assert confirm.status_code == 409
    reapplied = client.post(f"/api/role-change-previews/{preview_id}/apply", headers=admin["headers"])
    assert reapplied.status_code == 409

    stale_events = client.get("/api/audit?action=role_change.stale", headers=admin["headers"]).json()
    assert stale_events["total"] >= 1


def test_low_risk_change_applies_without_confirmation(client, admin, department):
    role = client.post(
        "/api/roles",
        headers=admin["headers"],
        json={"code": "reader", "name": "查看员", "permission_codes": ["affairs.read"]},
    ).json()
    create_user(client, admin, "clerk.reader", "读取员", ["reader"], department_id=department["id"])

    # 仅新增权限，无人失去能力 → 低风险
    preview = client.post(
        f"/api/roles/{role['id']}/change-previews",
        headers=admin["headers"],
        json={"permission_codes": ["affairs.read", "residents.read"]},
    ).json()
    assert preview["risk_level"] == "low"
    assert preview["impact"]["summary"]["users_gaining_count"] == 1

    applied = client.post(f"/api/role-change-previews/{preview['id']}/apply", headers=admin["headers"])
    assert applied.status_code == 200, applied.text
    assert applied.json()["reconciliation"]["approval"]["required"] is False
    assert role_permissions(client, admin, role["id"]) == ["affairs.read", "residents.read"]


def test_separation_of_duties_blocks_process(client, admin, department):
    role_a = client.post(
        "/api/roles",
        headers=admin["headers"],
        json={"code": "handler.a", "name": "办理角色甲", "permission_codes": ["petitions.write"]},
    ).json()
    role_b = client.post(
        "/api/roles",
        headers=admin["headers"],
        json={"code": "handler.b", "name": "办理角色乙", "permission_codes": ["petitions.write"]},
    ).json()
    create_user(client, admin, "clerk.alpha", "甲经办", ["handler.a"], department_id=department["id"])
    create_user(client, admin, "clerk.beta", "乙经办", ["handler.b"], department_id=department["id"])
    business = seed_in_flight_business(department["id"])
    append_flow(business["petition_id"], "提交办理结果", "甲经办")

    # 变更后只剩"甲经办"具备 petitions.write，而他是上一步操作人 → 职责分离卡死
    preview = client.post(
        f"/api/roles/{role_b['id']}/change-previews",
        headers=admin["headers"],
        json={"permission_codes": []},
    ).json()
    assert preview["risk_level"] == "high"
    sod = preview["impact"]["sod_blocked"]
    assert len(sod) == 1
    assert sod[0]["petition_id"] == business["petition_id"]
    assert sod[0]["last_operator"] == "甲经办"

    # 对照：保留乙的权限时无人被职责分离卡死
    safe_preview = client.post(
        f"/api/roles/{role_b['id']}/change-previews",
        headers=admin["headers"],
        json={"permission_codes": ["petitions.write"]},
    ).json()
    assert safe_preview["impact"]["sod_blocked"] == []
    assert safe_preview["risk_level"] == "low"


def test_cancelled_preview_cannot_be_applied(client, admin):
    role = client.post(
        "/api/roles",
        headers=admin["headers"],
        json={"code": "reader", "name": "查看员", "permission_codes": ["affairs.read"]},
    ).json()
    preview = client.post(
        f"/api/roles/{role['id']}/change-previews",
        headers=admin["headers"],
        json={"permission_codes": ["affairs.read", "residents.read"]},
    ).json()
    cancelled = client.post(f"/api/role-change-previews/{preview['id']}/cancel", headers=admin["headers"])
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"
    applied = client.post(f"/api/role-change-previews/{preview['id']}/apply", headers=admin["headers"])
    assert applied.status_code == 409
    assert role_permissions(client, admin, role["id"]) == ["affairs.read"]


def test_preview_listing_and_permission_checks(client, admin, department):
    role = client.post(
        "/api/roles",
        headers=admin["headers"],
        json={"code": "reader", "name": "查看员", "permission_codes": ["affairs.read"]},
    ).json()
    clerk = create_user(client, admin, "clerk.plain", "普通员", ["reader"], department_id=department["id"])
    clerk_session = login(client, "clerk.plain")

    # 没有 roles.write 的用户不能生成预演
    denied = client.post(
        f"/api/roles/{role['id']}/change-previews",
        headers=clerk_session["headers"],
        json={"permission_codes": ["affairs.read"]},
    )
    assert denied.status_code == 403

    preview = client.post(
        f"/api/roles/{role['id']}/change-previews",
        headers=admin["headers"],
        json={"permission_codes": ["affairs.read", "residents.read"]},
    )
    assert preview.status_code == 201

    listed = client.get(f"/api/roles/{role['id']}/change-previews", headers=admin["headers"])
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert listed.json()[0]["summary"]["users_gaining_count"] == 1
    assert "impact" not in listed.json()[0]

    # 未知权限编码 → 404
    missing = client.post(
        f"/api/roles/{role['id']}/change-previews",
        headers=admin["headers"],
        json={"permission_codes": ["no.such.permission"]},
    )
    assert missing.status_code == 404
