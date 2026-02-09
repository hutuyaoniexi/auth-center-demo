# Auth Center – Spring Boot 通用鉴权 Starter

一个 **低侵入、可插拔** 的 Spring Boot 鉴权 Starter，基于 **JWT + Token Store**，同时支持 **Spring Security 方法级鉴权** 与 **自定义权限注解**，适用于中小型系统或作为统一鉴权能力的基础模块。

> 设计目标：  
> **不接管业务安全策略，只补齐鉴权能力**

---

## ✨ 核心特性

- 🔐 **JWT 无状态鉴权**
    - Access Token + Refresh Token
    - 可配置 issuer / audience / 有效期 / 时钟偏移
- 🧩 **零侵入 Starter 设计**
    - 不创建 `SecurityFilterChain`
    - 仅通过 `HttpSecurityCustomizer` 做增量增强
- 🧠 **多种方法级鉴权模式（RBAC、细颗粒度）**
    - Spring Security 原生注解
    - 自定义 `@RequirePerm` 权限注解
    - 支持单独或组合启用
- 🔄 **Token 生命周期管理**
    - 登录 / 刷新 / 登出
    - Token 黑名单（可扩展为 Redis）
- 🧱 **SPI 扩展点**
    - 业务系统自定义用户加载逻辑
- 📦 **统一 JSON 异常响应**
    - 401 / 403 / Token 失效 / 权限不足

---

## 🧱 技术栈
- Java 17
- Spring Boot 3.x
- Spring Security 6
---

## 🏗️ 项目结构

```text
auth-center-demo
├── auth-center-spring-boot-starter   # 通用鉴权 Starter
│   ├── annotation        # 对外注解（@RequirePerm）
│   ├── aop               # 权限注解 AOP
│   ├── autoconfig        # 自动装配（不接管业务策略）
│   ├── exception         # 鉴权域异常 + 错误码（仅鉴权链路使用）
│   ├── filter            # JWT 认证过滤器
│   ├── permission        # 权限校验模型（Checker/Action）
│   ├── properties        # Starter 配置模型
│   ├── security          # Token 生成 / 刷新 / 登出
│   ├── spi               # 业务系统 SPI（用户加载等）
│   ├── store             # TokenStore（默认内存实现）
│   └── web               # 401/403 统一 JSON 输出（handler/response）
│
├── auth-center-example-app           # 示例业务系统
│   ├── config            # 业务侧安全配置（声明策略、白名单）
│   ├── controller        # 示例接口（登录/刷新/受保护接口）
│   ├── dto               # 请求响应 DTO
│   ├── permission        # 示例权限定义（Spring vs Starter 对照）
│   ├── service           # SPI 实现示例（DemoAuthUserService）
│   └── resources
│       └── application.yml
```

---

## 🚀 快速开始（5 分钟跑起来）

### 1️⃣ 引入 Starter

```xml
<dependency>
    <groupId>com.demo</groupId>
    <artifactId>auth-center-spring-boot-starter</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

---

### 2️⃣ 配置 application.yml

```yml
auth-center:
  method-security-mode: BOTH
  jwt:
    issuer: "auth-center-demo"
    audience:
      - "example-app"
    secret: "0123456789abcdef0123456789abcdef"
    access-ttl-seconds: 1800
    refresh-enabled: true
    refresh-ttl-seconds: 604800
    clock-skew-seconds: 30
```
### 方法级鉴权模式（`method-security-mode`）

用于控制 **方法级权限校验的启用方式**，支持以下模式：

| 模式 | 说明 |
|----|----|
| `NONE` | 不启用方法级鉴权，仅校验 JWT |
| `SPRING` | 启用 Spring Security 原生方法注解 |
| `REQUIRE_PERM` | 启用 Starter 的 `@RequirePerm` 注解 |
| `BOTH` | 同时启用两种方式（推荐） |

---

### 3️⃣ 实现用户 SPI（业务系统）

```java
@Component
public class DemoAuthUserService implements AuthUserService {

    @Override
    public AuthUser loadUserByUsername(String username) {
        return new AuthUser(
                "10001",
                username,
                List.of("USER"),
                List.of("api:read")
        );
    }
}
```

---

### 4️⃣ 使用权限注解

```java
@RequirePerm("api:read")
@GetMapping("/api/data")
public String readData() {
    return "ok";
}
```

---

## 🔄 Token 生命周期接口（示例）

| 接口 | 描述 |
|----|----|
| `POST /auth/login` | 登录 |
| `POST /auth/refresh` | 刷新 token |
| `POST /auth/logout` | 登出 |

---



## 🔐 权限校验示例接口（节选）

> 以下接口用于演示 **Spring Security 原生注解** 与 **Starter 自定义注解** 两种方式的对比使用。

| 分类 | 方法 | 路径 | 说明 |
|---|---|---|---|
| Spring 注解 | POST | `/api/admin/spring` | admin 可访问 |
| Spring 注解 | GET | `/api/query/spring` | user / admin 可访问 |
| Starter 注解 | POST | `/api/admin/starter` | admin 可访问 |
| Starter 注解 | GET | `/api/query/starter` | user / admin 可访问 |

---

## 🧪 Swagger

- http://localhost:8080/swagger-ui/index.html
- http://localhost:8080/v3/api-docs


---

## ❌ 错误返回规范

所有鉴权相关错误均以统一 JSON 结构返回，以简化前端与调用方的处理逻辑。

### 错误码

- `40101` 缺少 token
- `40102` token 过期
- `40103` token 非法 / 签名错误
- `40104` token 已失效
- `40301` 权限不足

### 401 未认证（示例）

```json
{
  "code": 401,
  "message": "Unauthorized",
  "path": "/api/user/me"
}
```

### 403 无权限（示例）

```json
{
  "code": 403,
  "message": "Access Denied",
  "path": "/api/admin/task"
}
```

---

## 🔐 安全说明

- JWT Secret 建议不少于 **256 bit**
- Access Token 建议短时有效（≤ **30 分钟**）
- Refresh Token 推荐存储于 **Redis** 并设置 TTL
- 生产环境必须使用 **HTTPS**

> 本项目不以替代完整身份认证中心（IdP）为目标。  
> 生产系统中建议额外考虑：密钥轮换、多端登录与强制下线、统一用户中心等问题。


---

## 🛣 Roadmap（非承诺）

- 基于 Redis 的 `TokenStore`
- 多端登录与强制下线
- OAuth2 / SSO 集成
- 多租户支持

> Roadmap 仅表示潜在演进方向，不构成实现承诺。

---

## 📌 总结

本项目展示了一种 **工程化、低侵入、可复用** 的 Spring Boot 鉴权设计方式：

- 鉴权能力封装在独立 Starter 中
- 业务系统通过最小 SPI 接入
- 权限规则清晰、可测试、低耦合

适用于 **中小规模系统或内部平台** 的统一鉴权需求。

---

## 📄 License

MIT
