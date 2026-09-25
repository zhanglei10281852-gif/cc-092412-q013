from __future__ import annotations


def _create_department(client, name="综合服务中心"):
    response = client.post("/departments", json={"name": name, "manager": "李主任", "phone": "010-12345678"})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _create_user(client, headers, username, role_codes, department_id=None, password="Clerk!23456"):
    response = client.post(
        "/api/users",
        headers=headers,
        json={
            "username": username,
            "password": password,
            "display_name": username,
            "role_codes": role_codes,
            "department_id": department_id,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _login(client, username, password="Clerk!23456"):
    response = client.post("/api/auth/login", json={"username": username, "password": password, "client_label": "tests"})
    assert response.status_code == 200, response.text
    body = response.json()
    return body["token"], {"Authorization": f"Bearer {body['token']}"}


def _grant_clerk_permissions(client, headers, codes):
    """低风险纯新增预演可由发起人直接确认应用。"""
    response = client.post(
        "/api/roles/clerk/rehearsals",
        headers=headers,
        json={"permission_codes": codes},
    )
    assert response.status_code == 201, response.text
    rehearsal = response.json()
    assert rehearsal["is_high_risk"] is False
    assert rehearsal["status"] == "approved"
    applied = client.post(f"/api/role-changes/{rehearsal['id']}/apply", headers=headers)
    assert applied.status_code == 200, applied.text
    return rehearsal["id"]


def _open_petition_in_department(client, department_id):
    petition = client.post(
        "/petitions",
        json={"type": "意见建议", "target": "村道照明", "content": "建议增设照明", "contact": "13800000000"},
    )
    assert petition.status_code == 201, petition.text
    petition_id = petition.json()["id"]
    assert client.post(f"/petitions/{petition_id}/receive").status_code == 200
    assign = client.post(f"/petitions/{petition_id}/assign", json={"department_id": department_id, "deadline_days": 5})
    assert assign.status_code == 200, assign.text
    return petition_id


def _open_affair_in_department(client, department_id):
    resident = client.post(
        "/residents",
        json={"name": "张三", "id_card": "110101199002021234", "gender": "男", "birth_date": "1990-02-02",
              "phone": "13800000001", "address": "幸福路一号", "village": "幸福村"},
    )
    assert resident.status_code == 201, resident.text
    resident_id = resident.json()["id"]
    affair = client.post(
        "/affairs",
        json={"title": "社保材料补录", "category": "社保", "applicant_id": resident_id, "description": "补录"},
    )
    assert affair.status_code == 201, affair.text
    affair_id = affair.json()["id"]
    processing = client.put(
        f"/affairs/{affair_id}/process",
        json={"status": "办理中", "department_id": department_id, "handler": "王经办"},
    )
    assert processing.status_code == 200, processing.text
    return affair_id


def test_low_risk_addition_can_self_apply_and_revokes_stale_sessions(client, admin):
    # 新建一个只读角色与成员，成员先登录持有旧权限的会话。
    role = client.post(
        "/api/roles",
        headers=admin["headers"],
        json={"code": "records.viewer", "name": "档案查看员", "permission_codes": ["residents.read"]},
    )
    assert role.status_code == 201, role.text
    _create_user(client, admin["headers"], "reader.one", ["records.viewer"])
    token, reader_headers = _login(client, "reader.one")

    rehearsal = client.post(
        "/api/roles/records.viewer/rehearsals",
        headers=admin["headers"],
        json={"permission_codes": ["residents.read", "affairs.read"], "comment": "增加事务查看"},
    )
    assert rehearsal.status_code == 201, rehearsal.text
    body = rehearsal.json()
    assert body["is_high_risk"] is False
    assert body["added_permissions"] == ["affairs.read"]
    assert body["removed_permissions"] == []
    affected = body["impact"]["affected_users"]
    assert [item["username"] for item in affected] == ["reader.one"]
    assert affected[0]["permissions_added"] == ["affairs.read"]
    assert body["status"] == "approved"

    applied = client.post(f"/api/role-changes/{body['id']}/apply", headers=admin["headers"])
    assert applied.status_code == 200, applied.text
    result = applied.json()
    assert result["status"] == "applied"

    # 旧会话携带旧权限快照，应用后必须重新登录。
    stale = client.get("/api/auth/me", headers=reader_headers)
    assert stale.status_code == 401
    _, new_headers = _login(client, "reader.one")
    me = client.get("/api/auth/me", headers=new_headers).json()
    assert "affairs.read" in me["permissions"]

    reconciliation = result["reconciliation"]
    assert reconciliation["matches_preview"] is True
    assert reconciliation["sessions"]["actually_revoked_count"] == 1
    assert reconciliation["sessions"]["preview_active_count"] == 1


def test_high_risk_rehearsal_lists_users_sessions_todos_and_sod_blocks(client, admin):
    department_id = _create_department(client)
    _grant_clerk_permissions(
        client, admin["headers"],
        ["affairs.read", "affairs.write", "petitions.read", "petitions.write", "residents.read"],
    )
    _create_user(client, admin["headers"], "worker.a", ["clerk"], department_id=department_id)
    worker_token, worker_headers = _login(client, "worker.a")

    petition_id = _open_petition_in_department(client, department_id)
    affair_id = _open_affair_in_department(client, department_id)

    # 收回 clerk 的信访办理权限：高风险。
    rehearsal = client.post(
        "/api/roles/clerk/rehearsals",
        headers=admin["headers"],
        json={"permission_codes": ["affairs.read", "affairs.write", "petitions.read", "residents.read"]},
    )
    assert rehearsal.status_code == 201, rehearsal.text
    body = rehearsal.json()
    assert body["is_high_risk"] is True
    assert body["status"] == "awaiting_approval"
    assert body["removed_permissions"] == ["petitions.write"]

    impact = body["impact"]
    affected = impact["affected_users"]
    assert len(affected) == 1
    assert affected[0]["username"] == "worker.a"
    assert affected[0]["permissions_removed"] == ["petitions.write"]
    assert affected[0]["permissions_added"] == []

    sessions = impact["active_sessions"]
    assert len(sessions) == 1
    assert sessions[0]["username"] == "worker.a"
    assert sessions[0]["will_revoke"] is True

    todo_types = impact["affected_todo_types"]
    assert len(todo_types) == 1
    assert todo_types[0]["business"] == "信访件"
    assert todo_types[0]["permission"] == "petitions.write"
    assert todo_types[0]["department_id"] == department_id
    assert todo_types[0]["open_count"] == 1
    assert petition_id in todo_types[0]["open_item_ids"]

    blocked = impact["sod_blocked_flows"]
    assert len(blocked) == 1
    assert blocked[0]["business"] == "信访件"
    assert blocked[0]["open_item_ids"] == [petition_id]
    assert blocked[0]["previous_handler_ids"] == [affected[0]["user_id"]]
    # 事务办理权保留，因此在途事务不受阻。
    assert all(item["business"] != "政务事务" for item in blocked)
    assert affair_id  # 仅用于固定在途事务确实存在
    assert impact["summary"] == {
        "affected_user_count": 1,
        "session_count": 1,
        "affected_todo_type_count": 1,
        "blocked_flow_count": 1,
    }
    assert body["state_snapshot"]["open_petitions"]
    assert len(body["state_version"]) == 64


def _second_admin(client, admin, username="admin.two"):
    _create_user(client, admin["headers"], username, ["administrator"])
    _, headers = _login(client, username)
    return headers


def test_high_risk_requires_distinct_second_admin_and_blocks_repeat(client, admin):
    _grant_clerk_permissions(client, admin["headers"], ["petitions.write"])
    second_headers = _second_admin(client, admin)
    rehearsal = client.post(
        "/api/roles/clerk/rehearsals",
        headers=admin["headers"],
        json={"permission_codes": []},
    ).json()
    rehearsal_id = rehearsal["id"]
    assert rehearsal["status"] == "awaiting_approval"

    # 未确认前不能应用。
    early_apply = client.post(f"/api/role-changes/{rehearsal_id}/apply", headers=admin["headers"])
    assert early_apply.status_code == 409

    # 发起人不能确认自己的高风险变更。
    self_approve = client.post(
        f"/api/role-changes/{rehearsal_id}/approve", headers=admin["headers"], json={"comment": "自批"}
    )
    assert self_approve.status_code == 403

    # 第二位管理员确认。
    approved = client.post(
        f"/api/role-changes/{rehearsal_id}/approve", headers=second_headers, json={"comment": "同意"}
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"
    assert approved.json()["approved_by_name"] == "admin.two"

    # 重复确认一律拒绝，且任何管理员都不能再就同一预演表态。
    repeat = client.post(f"/api/role-changes/{rehearsal_id}/approve", headers=second_headers, json={"comment": "再批"})
    assert repeat.status_code == 409
    initiator_repeat = client.post(
        f"/api/role-changes/{rehearsal_id}/reject", headers=admin["headers"], json={"comment": "反悔"}
    )
    assert initiator_repeat.status_code == 409

    applied = client.post(f"/api/role-changes/{rehearsal_id}/apply", headers=admin["headers"])
    assert applied.status_code == 200, applied.text
    # 重复应用不能再次修改权限。
    second_apply = client.post(f"/api/role-changes/{rehearsal_id}/apply", headers=admin["headers"])
    assert second_apply.status_code == 409


def test_rejected_rehearsal_cannot_apply(client, admin):
    _grant_clerk_permissions(client, admin["headers"], ["affairs.read"])
    second_headers = _second_admin(client, admin)
    rehearsal = client.post(
        "/api/roles/clerk/rehearsals",
        headers=admin["headers"],
        json={"permission_codes": []},
    ).json()
    rejected = client.post(
        f"/api/role-changes/{rehearsal['id']}/reject", headers=second_headers, json={"comment": "不同意"}
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"
    denied = client.post(f"/api/role-changes/{rehearsal['id']}/apply", headers=admin["headers"])
    assert denied.status_code == 409
    # 权限保持不变。
    role = client.get("/api/roles/clerk", headers=admin["headers"]).json()
    assert [item["code"] for item in role["permissions"]] == ["affairs.read"]


def test_stale_rehearsal_rejected_when_role_assignments_change(client, admin):
    department_id = _create_department(client)
    _grant_clerk_permissions(client, admin["headers"], ["petitions.write"])
    worker = _create_user(client, admin["headers"], "worker.b", ["clerk"], department_id=department_id)
    _open_petition_in_department(client, department_id)
    second_headers = _second_admin(client, admin)

    rehearsal = client.post(
        "/api/roles/clerk/rehearsals",
        headers=admin["headers"],
        json={"permission_codes": []},
    ).json()

    # 预演之后把用户改挂到一个无权限角色，用户角色分配变化，指纹随之改变。
    no_role = client.post(
        "/api/roles", headers=admin["headers"], json={"code": "no.access", "name": "无权限角色", "permission_codes": []}
    )
    assert no_role.status_code == 201, no_role.text
    replaced = client.put(f"/api/users/{worker['id']}/roles", headers=admin["headers"], json={"role_codes": ["no.access"]})
    assert replaced.status_code == 200, replaced.text

    stale = client.post(
        f"/api/role-changes/{rehearsal['id']}/approve", headers=second_headers, json={"comment": "同意"}
    )
    assert stale.status_code == 409
    detail = client.get(f"/api/role-changes/{rehearsal['id']}", headers=admin["headers"]).json()
    assert detail["status"] == "expired"

    # 旧预演连应用也不允许。
    denied = client.post(f"/api/role-changes/{rehearsal['id']}/apply", headers=admin["headers"])
    assert denied.status_code == 409
    # 权限没有被改动。
    role = client.get("/api/roles/clerk", headers=admin["headers"]).json()
    assert [item["code"] for item in role["permissions"]] == ["petitions.write"]


def test_stale_rehearsal_rejected_when_business_state_changes(client, admin):
    department_id = _create_department(client)
    _grant_clerk_permissions(
        client, admin["headers"],
        ["petitions.read", "petitions.write"],
    )
    _create_user(client, admin["headers"], "worker.c", ["clerk"], department_id=department_id)
    petition_id = _open_petition_in_department(client, department_id)
    second_headers = _second_admin(client, admin)

    rehearsal = client.post(
        "/api/roles/clerk/rehearsals",
        headers=admin["headers"],
        json={"permission_codes": ["petitions.read"]},
    ).json()
    assert client.post(
        f"/api/role-changes/{rehearsal['id']}/approve", headers=second_headers, json={"comment": "同意"}
    ).status_code == 200

    # 在途信访办结，业务状态版本变化，已批准的旧预演同样不得使用。
    assert client.post(f"/petitions/{petition_id}/process", json={"result": "已处理"}).status_code == 200
    review = client.post(f"/petitions/{petition_id}/review", json={"passed": True, "review_opinion": "通过"})
    assert review.status_code == 200, review.text

    denied = client.post(f"/api/role-changes/{rehearsal['id']}/apply", headers=admin["headers"])
    assert denied.status_code == 409
    detail = client.get(f"/api/role-changes/{rehearsal['id']}", headers=admin["headers"]).json()
    assert detail["status"] == "expired"


def test_apply_revokes_sessions_and_writes_reconciliation_and_audit(client, admin):
    department_id = _create_department(client)
    _grant_clerk_permissions(
        client, admin["headers"],
        ["affairs.read", "affairs.write", "petitions.read", "petitions.write"],
    )
    worker = _create_user(client, admin["headers"], "worker.d", ["clerk"], department_id=department_id)
    worker_token, worker_headers = _login(client, "worker.d")
    _open_petition_in_department(client, department_id)
    second_headers = _second_admin(client, admin)

    rehearsal = client.post(
        "/api/roles/clerk/rehearsals",
        headers=admin["headers"],
        json={"permission_codes": ["affairs.read", "affairs.write", "petitions.read"]},
    ).json()
    client.post(f"/api/role-changes/{rehearsal['id']}/approve", headers=second_headers)

    applied = client.post(f"/api/role-changes/{rehearsal['id']}/apply", headers=admin["headers"])
    assert applied.status_code == 200, applied.text
    result = applied.json()

    # 角色权限确实被收回。
    role = client.get("/api/roles/clerk", headers=admin["headers"]).json()
    assert "petitions.write" not in [item["code"] for item in role["permissions"]]

    # 失权用户旧会话被撤销。
    assert client.get("/api/auth/me", headers=worker_headers).status_code == 401
    _, relogin_headers = _login(client, "worker.d")
    permissions = client.get("/api/auth/me", headers=relogin_headers).json()["permissions"]
    assert "petitions.write" not in permissions
    assert "affairs.write" in permissions

    reconciliation = result["reconciliation"]
    assert reconciliation["matches_preview"] is True
    assert reconciliation["users"]["actual_affected_user_ids"] == [worker["id"]]
    assert reconciliation["sessions"]["actually_revoked_count"] == 1
    assert reconciliation["approval"]["created_by"] == "系统管理员"
    assert reconciliation["approval"]["approved_by"] == "admin.two"
    assert reconciliation["sod_blocked_flows"]["actual"] == [
        {"department_id": department_id, "permission": "petitions.write"}
    ]

    # 审计中同时留下批准与实际变化记录。
    events = client.get("/api/audit?action=role.update", headers=admin["headers"]).json()
    role_updates = [item for item in events["data"] if str(item["resource_id"]) == str(role["id"])]
    assert role_updates and role_updates[0]["metadata_json"]
    import json
    metadata = json.loads(role_updates[0]["metadata_json"])
    assert metadata["rehearsal_id"] == rehearsal["id"]
    assert metadata["sessions_revoked"] == 1
    approve_events = client.get("/api/audit?action=role.change.approve", headers=admin["headers"]).json()
    assert approve_events["total"] == 1


def test_direct_permission_patch_is_rejected(client, admin):
    response = client.patch(
        "/api/roles/clerk",
        headers=admin["headers"],
        json={"permission_codes": ["residents.read"]},
    )
    assert response.status_code == 422
    # 仅文案修改仍允许直接更新。
    renamed = client.patch("/api/roles/clerk", headers=admin["headers"], json={"name": "综合经办员（改）"})
    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["name"] == "综合经办员（改）"


def test_rehearsal_listing_and_permission_guard(client, admin):
    _grant_clerk_permissions(client, admin["headers"], ["affairs.read"])
    created = client.post(
        "/api/roles/clerk/rehearsals",
        headers=admin["headers"],
        json={"permission_codes": []},
    ).json()

    # 无 roles.read 的用户不能查看预演。
    _create_user(client, admin["headers"], "plain.user", [])
    _, plain_headers = _login(client, "plain.user")
    assert client.get("/api/role-changes", headers=plain_headers).status_code == 403
    assert client.get(f"/api/role-changes/{created['id']}", headers=plain_headers).status_code == 403

    listing = client.get("/api/role-changes?status=awaiting_approval", headers=admin["headers"])
    assert listing.status_code == 200
    assert any(item["id"] == created["id"] for item in listing.json())
