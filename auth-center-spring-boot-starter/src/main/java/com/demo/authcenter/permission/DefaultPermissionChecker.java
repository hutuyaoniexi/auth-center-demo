package com.demo.authcenter.permission;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Objects;

/**
 * 默认权限判定
 * <p>
 * 约定：权限以字符串表示（如 "order:read"），通常由 JwtAuthFilter 写入 Authentication。
 * <p>
 * 业务可替换 PermissionChecker 以支持角色映射、通配符、ABAC 等策略。
 */
public class DefaultPermissionChecker implements PermissionChecker {

    /**
     * 当用户的 authorities 中包含目标权限字符串时返回 true。
     *
     * @param authentication 当前用户身份信息
     * @param perm           权限字符串（如 "order:read"）
     * @return
     */
    @Override
    public boolean hasPerm(Authentication authentication, String perm) {
        // 空权限处理
        if (authentication == null || !authentication.isAuthenticated()) return false;
        if (perm == null || perm.isBlank()) return false;
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        if (authorities == null || authorities.isEmpty()) return false;

        for (GrantedAuthority ga : authorities) {
            if (ga != null && Objects.equals(perm, ga.getAuthority())) {
                return true;
            }
        }
        return false;
    }
}
