攻击者先把自己的会话号发给受害者，受害者登录后这个会话号直接变成了登录态：登录成功必须重新生成会话标识；旧标识必须立刻失效；会话标识必须不可预测且长度足够；登录前与会话后的标识不得相同；并发登录不得共用标识；批量处理各会话独立。不变量：登录前后的会话标识必然不同；旧标识在任何情况下都不再有效。

## 场景

调用方先为匿名访客创建登录前会话，认证成功后轮换标识、绑定用户，再把新标识交给浏览器。后续请求只应接受仍然存在于会话存储中的标识。本仓库提供一个会话模块和一组公开测试，测试描述的是调用方依赖的契约。

## 接口

所有函数都从 fixation 包导入。

- issue_pre_login(store, entropy, now) 创建登录前会话。返回的字典至少包含 id、user、pre_login、created 四个键，并写入会话存储。
- rotate(store, session, entropy, now) 在认证成功后调用。返回全新的会话记录，标识与传入会话不同，旧标识立即失效，原会话上已绑定的用户被保留。
- invalidate(store, session_id, now) 使指定标识失效。返回字典包含 session_id、invalidated、effective 三个键。
- check_entropy(session_id, policy) 当标识长度达到 policy 的 min_length 且每个字符都位于 policy 的 charset 时返回 True，否则返回 False。
- bind_user(store, session, user, now) 把 user 绑定到会话，并保证会话存储中的记录同步更新，返回更新后的记录。
- check_reuse(old, new) 当 new 可以作为 old 的替代标识时返回 True；两者相同或 new 为空时返回 False。
- validate_policy(policy) 返回策略问题代码列表。检查策略是否要求登录轮换、最小长度是否足够、是否要求旧标识失效。
- login_batch(attempts, store, now) 批量登录。attempts 是包含 user 键的字典列表，返回 sessions 列表与 count，各会话互相独立。

## 会话存储

store 是普通字典。store 的 sessions 键对应一个映射，键为会话标识，值为会话记录。会话记录包含 id、user、pre_login、created，绑定用户后还可能包含 bound_at。失效的标识不再出现在该映射中。

## 策略与熵源

policy 是字典，使用 min_length、charset、rotate_on_login、invalidate_old 四个键。DEFAULT_POLICY 提供默认值，其中长度下限为 32，字符集为 URL 安全字母表。

entropy 是调用方提供的可调用对象，接收一个整数并返回字符串，其返回值直接作为新会话标识。调用方会用它注入可预测或可观测的序列来检查实现是否真的使用了熵源。

## 运行测试

在仓库根目录执行：

    python -m pytest tests -q

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

