package com.demo.authcenter.aop;

import com.demo.authcenter.annotation.RequirePerm;
import com.demo.authcenter.permission.PermissionAction;
import com.demo.authcenter.permission.PermissionChecker;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.lang.reflect.Method;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 拦截 @RequirePerm，并在调用目标方法前做授权校验。
 * <p>
 * 优先级与兼容：
 * 1) perms() 非空：直接使用 perms
 * 2) 否则使用 perm + actions（兼容旧写法）
 * 3) perms 与 actions 同时配置：抛异常（避免歧义）
 */
@Aspect
public class RequirePermAspect {

    private final PermissionChecker checker;

    public RequirePermAspect(PermissionChecker checker) {
        this.checker = Objects.requireNonNull(checker, "PermissionChecker must not be null");
    }

    /**
     * 拦截 类 + 方法上的RequirePerm注解
     */
    @Before("@within(com.demo.authcenter.annotation.RequirePerm) || @annotation(com.demo.authcenter.annotation.RequirePerm)")
    public void check(JoinPoint jp) {
        // 1) 获取当前用户认证信息（用户信息 + 权限）
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) {
            throw new AccessDeniedException("Forbidden");
        }

        // 2) 获取被调用的方法
        Method method = ((MethodSignature) jp.getSignature()).getMethod();

        // 3) 算出“最终需要的权限/角色”
        Effective eff = resolveEffective(method);

        if (eff.roles.isEmpty() && eff.perms.isEmpty()) {
            throw new IllegalArgumentException("@RequirePerm must declare at least one of roles() or perms()/actions()");
        }

        // 4) 校验 角色 + 权限 （调用PermissionChecker ）
        boolean roleOk = eff.roles.isEmpty() || hasAnyRole(auth, eff.roles);
        boolean permOk = eff.perms.isEmpty() || hasAnyPerm(auth, eff.perms);

        boolean passed = (eff.mode == RequirePerm.Mode.ALL)
                ? (roleOk && permOk)
                : (roleOk || permOk);

        if (!passed) {
            throw new AccessDeniedException("Forbidden");
        }
    }

    /**
     * 类注解 + 方法注解合并（方法优先）：
     * - roles/perms/actions：类 + 方法合并去重
     * - perm：方法非 Dummy 则覆盖类
     * - mode：方法优先
     */
    private Effective resolveEffective(Method method) {
        RequirePerm onMethod = method.getAnnotation(RequirePerm.class);
        RequirePerm onClass = method.getDeclaringClass().getAnnotation(RequirePerm.class);

        RequirePerm base = (onClass != null) ? onClass : onMethod;
        RequirePerm override = (onMethod != null) ? onMethod : null;

        if (base == null) {
            throw new IllegalStateException("No @RequirePerm found");
        }

        // base
        RequirePerm.Mode mode = base.mode();
        String[] roles = base.roles();

        String[] perms = base.perms();
        Class<? extends Enum<?>> permEnum = base.perm();
        String[] actions = base.actions();

        // override (method wins)
        if (override != null) {
            roles = union(roles, override.roles());
            perms = union(perms, override.perms());
            actions = union(actions, override.actions());
            mode = override.mode();

            if (override.perm() != RequirePerm.Dummy.class) {
                permEnum = override.perm();
            }
        }

        List<String> requiredRoles = normalizeRoles(roles);
        List<String> requiredPerms = resolveFinalPerms(perms, permEnum, actions);

        return new Effective(mode, requiredRoles, requiredPerms);
    }

    /**
     * 最终权限来源规则：
     * <p>
     * - perms 非空：用 perms（推荐）
     * - perms 为空：用 permEnum + actions（兼容）
     * - perms 与 actions 同时非空：抛异常（避免两套都写造成歧义）
     */
    private static List<String> resolveFinalPerms(String[] perms,
                                                  Class<? extends Enum<?>> permEnum,
                                                  String[] actions) {
        boolean hasPerms = perms != null && perms.length > 0;
        boolean hasActions = actions != null && actions.length > 0;

        if (hasPerms && hasActions) {
            throw new IllegalArgumentException("@RequirePerm: do not set both perms() and actions()");
        }

        if (hasPerms) {
            return normalizePerms(perms);
        }
        // 兼容旧写法
        return resolvePermsByEnum(permEnum, actions);
    }

    /**
     * 合并去重 + trim + 过滤空白
     */
    private static String[] union(String[] a, String[] b) {
        LinkedHashSet<String> set = new LinkedHashSet<>();
        addAll(set, a);
        addAll(set, b);
        return set.toArray(new String[0]);
    }

    private static void addAll(Set<String> set, String[] arr) {
        if (arr == null) return;
        for (String s : arr) {
            if (s == null) continue;
            String v = s.trim();
            if (!v.isEmpty()) set.add(v);
        }
    }

    /**
     * "ADMIN" -> "ROLE_ADMIN"，"ROLE_ADMIN" 保持不变
     */
    private static List<String> normalizeRoles(String[] roles) {
        if (roles == null || roles.length == 0) return List.of();
        List<String> res = new ArrayList<>(roles.length);
        for (String r : roles) {
            if (r == null || r.isBlank()) {
                throw new IllegalArgumentException("@RequirePerm.roles() contains blank role");
            }
            String role = r.trim();
            res.add(role.startsWith("ROLE_") ? role : "ROLE_" + role);
        }
        return res;
    }

    /**
     * perms 字符串归一化（trim + 过滤空白）
     */
    private static List<String> normalizePerms(String[] perms) {
        List<String> res = new ArrayList<>(perms.length);
        for (String p : perms) {
            if (p == null || p.isBlank()) {
                throw new IllegalArgumentException("@RequirePerm.perms() contains blank perm");
            }
            res.add(p.trim());
        }
        return res;
    }

    /**
     * 兼容旧写法：从 perm enum + actions 推导权限字符串列表。
     * <p>
     * - actions 为空：不做枚举权限校验（只校验 roles）
     * - actions 非空：必须指定 permEnum，且枚举需实现 PermissionAction
     */
    private static List<String> resolvePermsByEnum(Class<? extends Enum<?>> enumClass, String[] actions) {
        if (actions == null || actions.length == 0) return List.of();
        if (enumClass == null || enumClass == RequirePerm.Dummy.class) {
            throw new IllegalArgumentException("@RequirePerm.perm() must be set when actions() is not empty");
        }

        List<String> perms = new ArrayList<>(actions.length);
        for (String action : actions) {
            if (action == null || action.isBlank()) {
                throw new IllegalArgumentException("@RequirePerm.actions() contains blank action");
            }
            perms.add(resolveOne(enumClass, action.trim()));
        }
        return perms;
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private static String resolveOne(Class<? extends Enum<?>> enumClass, String name) {
        final Enum e;
        try {
            e = Enum.valueOf((Class) enumClass, name);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException(
                    "Unknown action '" + name + "' for enum " + enumClass.getName(), ex
            );
        }

        if (!(e instanceof PermissionAction p)) {
            throw new IllegalArgumentException(
                    "Enum " + enumClass.getName() + " must implement " + PermissionAction.class.getName()
            );
        }
        return p.value();
    }

    private static boolean hasAnyRole(Authentication auth, List<String> requiredRoles) {
        Set<String> authorities = toAuthoritySet(auth);
        return requiredRoles.stream().anyMatch(authorities::contains);
    }

    private boolean hasAnyPerm(Authentication auth, List<String> requiredPerms) {
        return requiredPerms.stream().anyMatch(p -> checker.hasPerm(auth, p));
    }

    private static Set<String> toAuthoritySet(Authentication auth) {
        Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
        if (authorities == null || authorities.isEmpty()) return Set.of();
        return authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
    }

    private record Effective(RequirePerm.Mode mode, List<String> roles, List<String> perms) {
    }
}
