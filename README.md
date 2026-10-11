# shell-rs-server

ShellRS 的云同步服务端：把一个人在多台设备上的主机、分组、凭据（含密码和私钥）、端口转发、命令片段和设置保持一致。

**服务端只存密文。** 云密码在设备上经 argon2id 派生成两半：主密钥只留在设备上，认证密钥发来登录。每条记录在设备上用一把随机的 vault key（XChaCha20-Poly1305）加密，vault key 再用主密钥包好存在这里。数据库连同备份被人拿走也解不开；代价是忘了云密码，云端的数据就找不回来了。

## 构建与测试

```bash
go test -race ./...
go vet ./...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o shell-rs-server .
```

用的是纯 Go 的 `modernc.org/sqlite`，不需要 cgo，在 Windows 上也能直接交叉编译。

## 部署（gz）

用 supervisor 托管（`deploy/supervisor.conf`），只监听 `127.0.0.1:18090`，日志在 `/root/shell-rs-server/logs/server.log`。

```bash
mkdir -p /root/shell-rs-server/data /root/shell-rs-server/logs
# 上传 shell-rs-server 到 /root/shell-rs-server/
cp deploy/supervisor.conf /etc/supervisor/conf.d/shell-rs-server.conf
supervisorctl reread && supervisorctl update shell-rs-server
supervisorctl status shell-rs-server
```

升级：上传新的二进制（先传成 `shell-rs-server.new` 再 `mv`），然后 `supervisorctl restart shell-rs-server`。

nginx：把 `deploy/nginx-location.conf` 放进 `shell.wcy9.com.conf` 的 443 段，`nginx -t` 后 reload。`-trust-proxy` 让登录限流按 nginx 给的 `X-Real-IP` 计。

## 账号

只有管理员能建账号，没有注册接口。

```bash
cd /root/shell-rs-server
./shell-rs-server user add <名字> -db data/sync.db      # 输入两遍密码，至少 8 个字符
./shell-rs-server user list -db data/sync.db
./shell-rs-server user passwd <名字> -db data/sync.db   # 会清空此人云端的数据和登录
./shell-rs-server user delete <名字> -db data/sync.db
```

改密码会清空云端：那些数据是用旧密码派生的密钥加密的。各设备下次同步时用新密码登录，再把本机的数据传上来。

## 协议

JSON，二进制字段是 base64。除 `prelogin`、`login`、`health` 外都要 `Authorization: Bearer <token>`。

| 请求 | 说明 |
|---|---|
| `POST /api/prelogin {username}` | → `{salt, time, memory, threads}`：设备据此跑 argon2id，输出 64 字节，前 32 是主密钥，后 32 是认证密钥。没有这个账号也照样给一个固定的假盐 |
| `POST /api/login {username, auth_key, device}` | → `{token, vault_key}`（还没有 vault key 时为 `null`）。同一 IP 或账号 15 分钟内失败 10 次就回 429 |
| `POST /api/logout` | 作废这个 token |
| `GET /api/vault-key`、`PUT /api/vault-key {vault_key}` | 第一台设备设好包好的 vault key；已经有了就回 409 并带上现有的 |
| `GET /api/records?since=N` | → `{records, more, revision}`：revision 大于 N 的记录按顺序给，一次最多 500 条，`more` 为真就接着要 |
| `POST /api/records {records: [{id, base_revision, deleted, data}]}` | → `{applied, conflicts, revision}`。服务器上这条的 revision 不是 `base_revision` 的放进 `conflicts`（带服务器上的样子），其余一次事务写入，各得一个新 revision |

记录的 `id` 是 1–64 个 `[A-Za-z0-9_:-]`，类型和内容都在密文里，服务端只按 revision 排序。删除是墓碑（`deleted: true`，`data` 为空），一直留着，好让别的设备也删掉。
