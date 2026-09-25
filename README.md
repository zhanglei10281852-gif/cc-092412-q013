# 乡镇政务协同服务

这是一个面向乡镇综合服务中心的模块化后端，集中管理居民档案、政务事务、信访流转、公告、部门、用户、角色、权限、会话、审计和可恢复后台任务。项目使用 FastAPI 与 SQLite，所有运行数据保存在单个本地数据库文件中，不依赖另行部署的数据库、缓存或消息队列。

## 主要模块

- 居民档案：登记、查询、更新和关联事务。
- 事务办理：受理、分派、退回、办结和部门责任查询。
- 信访流转：签收、分派、办理、审核、复查、催办和流转记录。
- 公告与部门：公告置顶、分类检索、部门信息及关联业务查看。
- 身份与权限：用户、角色、细粒度权限、会话令牌、账号停用和会话撤销。
- 角色变更管控：权限调整前生成可保存的影响预演，高风险变更双人确认，按数据版本校验应用，应用后撤销旧会话并留存对账记录。
- 审计记录：关键身份操作留痕，并对口令和令牌等敏感字段做过滤。
- 后台任务：使用 SQLite 保存待执行任务，支持去重、租约、重试和完成回执。

## 运行环境

- Python 3.11
- SQLite 3，由 Python 标准库提供
- Linux、macOS 或 Windows

## 安装

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

配置项均以 `TOWNSHIP_` 开头。可以复制 `.env.example` 后按需设置，默认数据库位于 `./data/township.db`。

## 初始化与检查

```bash
python -m app.cli init-db
python -m app.cli check-db
```

## 启动服务

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8432
```

健康检查：

```bash
curl -sS http://127.0.0.1:8432/api/system/health
```

首次部署可创建唯一的初始管理员：

```bash
curl -sS -X POST http://127.0.0.1:8432/api/auth/bootstrap   -H 'Content-Type: application/json'   -d '{"username":"admin","password":"Admin!23456","client_label":"initial-setup"}'
```

之后通过 `/api/auth/login` 获取会话令牌，并在管理接口请求头中使用 `Authorization: Bearer <token>`。

## 测试

```bash
python -m pytest
```

测试覆盖身份初始化、登录、用户与角色维护、权限计算、账号停用后的会话撤销、审计脱敏、居民事务、信访状态流转、公告排序、后台任务去重与领取，以及数据库时间格式。

## 编译检查

```bash
python -m compileall -q app tests
```

## API 冒烟

```bash
python -m app.cli smoke
```

该命令在进程内启动应用并检查服务根路径与健康接口，适合部署前快速确认路由和数据库初始化是否正常。

## 目录结构

```text
app/
  api/             用户、角色、审计、认证和系统接口
  core/            时钟、安全、异常和分页能力
  repositories/    SQLite 查询与持久化读取
  routers/         居民、事务、公告、部门和信访业务接口
  schemas/         管理接口输入模型
  services/        身份、审计和后台任务领域服务
  cli.py           初始化、检查和冒烟入口
  database.py      SQLite 连接、事务、表结构与基础权限
tests/             核心、管理接口和原有业务回归测试
tools/             本地维护脚本
```

## 角色权限变更管控

直接 `PATCH /api/roles/{id}` 修改 `permission_codes` 已被禁用，权限集合的任何调整都必须走预演流程：

1. **生成预演**：`POST /api/roles/{角色ID或编码}/rehearsals`，提交目标完整权限清单。系统在确定的数据版本上保存快照与 SHA-256 版本指纹，并返回影响预演：
   - `affected_users`：会新增或失去能力的用户及其权限差异；
   - `active_sessions`：这些用户仍在使用、应用后将被撤销的会话；
   - `affected_todo_types`：失去办理权后受影响的在途待办类型（按部门聚合的在途事务、信访）；
   - `sod_blocked_flows`：因职责分离导致变更后无人能够继续办理的在途流程。
2. **确认**：只要包含权限收回即为高风险（`is_high_risk=true`），必须由另一位具备 `roles.write` 的管理员调用 `POST /api/role-changes/{id}/approve`；确认者不能是发起人。纯新增权限为低风险，可由发起人直接应用。
3. **应用**：`POST /api/role-changes/{id}/apply`。应用前重算版本指纹，自预演以来用户角色、权限或在途业务状态一旦变化（或预演超过有效期），旧结果一律拒绝（409）并标记失效，必须重新预演。
4. **收尾**：应用成功后撤销实际能力发生变化用户的旧会话，并在预演记录中写入 `reconciliation`（预演 vs 实际变化对账），审计中同时保留预演、批准与实际变更记录。重复确认、重复应用都不会再次修改权限。

`GET /api/role-changes` 与 `GET /api/role-changes/{id}` 可查询预演、确认记录与对账结果。

## 数据一致性

SQLite 连接默认启用外键、WAL、busy timeout 与同步写入策略。需要跨多张表更新的管理操作在即时事务中执行，失败会整体回滚。会话令牌只保存摘要；用户停用会撤销仍有效的会话。审计事件保存操作者、动作、资源、结果和前后状态，但不会保存明文密码或令牌。
