# 乡镇政务协同服务

这是一个面向乡镇综合服务中心的模块化后端，集中管理居民档案、政务事务、信访流转、公告、部门、用户、角色、权限、会话、审计和可恢复后台任务。项目使用 FastAPI 与 SQLite，所有运行数据保存在单个本地数据库文件中，不依赖另行部署的数据库、缓存或消息队列。

## 主要模块

- 居民档案：登记、查询、更新和关联事务。
- 事务办理：受理、分派、退回、办结和部门责任查询。
- 信访流转：签收、分派、办理、审核、复查、催办和流转记录。
- 公告与部门：公告置顶、分类检索、部门信息及关联业务查看。
- 身份与权限：用户、角色、细粒度权限、会话令牌、账号停用和会话撤销。
- 角色变更预演：权限调整前生成可保存的影响预演，基于确定的数据版本，高风险变更需第二管理员确认，应用后撤销受影响会话并留存对账记录。
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

## 角色变更预演

调整角色权限前，先为角色生成一份影响预演，确认无误后再应用：

```bash
# 1. 生成预演（permission_codes 为变更后的完整权限集合）
curl -sS -X POST http://127.0.0.1:8432/api/roles/3/change-previews \
  -H "Authorization: Bearer <token>" -H 'Content-Type: application/json' \
  -d '{"permission_codes":["affairs.read"]}'

# 2. 查看预演详情与影响分析
curl -sS http://127.0.0.1:8432/api/role-change-previews/1 \
  -H "Authorization: Bearer <token>"

# 3. 高风险变更需另一位管理员确认（确认者不能是预演发起人）
curl -sS -X POST http://127.0.0.1:8432/api/role-change-previews/1/confirm \
  -H "Authorization: Bearer <second-admin-token>"

# 4. 应用变更；重复应用幂等，不会再次修改权限
curl -sS -X POST http://127.0.0.1:8432/api/role-change-previews/1/apply \
  -H "Authorization: Bearer <token>"
```

预演的影响分析包括：会失去或新增权限的用户（按账号净变化计算，含其他角色兜底）、这些用户仍在使用的会话、受影响的在途事务与信访（按类型和承办部门聚合，含变更后无人可办的事项），以及因职责分离（相邻两步流转不得由同一人完成）而无法继续的信访流程。

每份预演绑定生成时刻的数据版本指纹。确认或应用时若用户角色、权限或在途业务已变化，预演会被标记为 `stale` 并拒绝使用，需要重新生成。高风险（有用户失去权限、有在途事项无人可办或有流程被职责分离卡死）的变更必须经第二位管理员确认；应用成功后系统自动撤销受影响用户的活跃会话，并在预演单上留存预演、批准与实际变化的对账记录。低风险变更可跳过确认直接应用，预演单也可以在应用前取消。

## 数据一致性

SQLite 连接默认启用外键、WAL、busy timeout 与同步写入策略。需要跨多张表更新的管理操作在即时事务中执行，失败会整体回滚。会话令牌只保存摘要；用户停用会撤销仍有效的会话。审计事件保存操作者、动作、资源、结果和前后状态，但不会保存明文密码或令牌。
