package com.demo.authcenter.spi;

/**
 * 业务系统提供用户加载能力，Starter 只依赖此接口。
 */
public interface AuthUserService {

    /**
     * 登录/签发 token：根据用户名加载用户信息（业务自定义 username 含义：账号/邮箱/手机号等）。
     */
    AuthUser loadByUsername(String username);

    /**
     * 鉴权阶段：根据 userId 加载用户信息（来自 token 的 sub）。
     */
    AuthUser loadByUserId(Long userId);
}
