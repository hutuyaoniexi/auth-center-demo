package com.demo.authcenter.filter;

import com.demo.authcenter.exception.AuthErrorCodes;
import com.demo.authcenter.security.JwtUtil;
import com.demo.authcenter.spi.AuthUserService;
import com.demo.authcenter.store.TokenStore;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.Objects;

/**
 * JWT 鉴权过滤器
 * <p>
 * 功能：仅在请求携带 Bearer Token 时尝试认证并写入 SecurityContext。
 * <p>
 * 约定：Authorization: Bearer token ，sub=userId，authorities 为角色/权限字符串。
 * <p>
 * 策略：若未携带 token，则不做任何标记，按匿名请求放行，由业务侧授权规则决定是否需要认证。
 */
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final TokenStore tokenStore;
    private final AuthUserService authUserService;

    public JwtAuthFilter(JwtUtil jwtUtil,
                         TokenStore tokenStore,
                         AuthUserService authUserService) {
        this.jwtUtil = Objects.requireNonNull(jwtUtil, "jwtUtil must not be null");
        this.tokenStore = Objects.requireNonNull(tokenStore, "tokenStore must not be null");
        this.authUserService = Objects.requireNonNull(authUserService, "authUserService must not be null");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {

        // 已认证则不重复解析
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            chain.doFilter(req, res);
            return;
        }

        // 1️⃣ 取token
        String token = jwtUtil.extractBearerToken(req.getHeader("Authorization"));
        // 无 token：不标记错误码，直接放行（交给业务授权规则决定）
        if (token == null) {
            chain.doFilter(req, res);
            return;
        }

        try {
            // 2️⃣ 检验
            Claims claims = jwtUtil.parseAndValidate(token);
            jwtUtil.validateAudience(claims);
            jwtUtil.validateAccessType(claims);

            String jti = jwtUtil.getJti(claims);
            if (jti == null || jti.isBlank()) {
                throw new IllegalArgumentException("Missing jti");
            }
            if (tokenStore.isBlacklisted(jti)) {
                SecurityContextHolder.clearContext();
                mark(req, AuthErrorCodes.CODE_TOKEN_BLACKLISTED);
                chain.doFilter(req, res);
                return;
            }

            Long userId = jwtUtil.getUserId(claims);
            if (userId == null) {
                throw new IllegalArgumentException("Missing or invalid sub(userId)");
            }

            // 3️⃣ 获取用户信息 & 权限
            var user = authUserService.loadByUserId(userId);
            if (user == null) {
                throw new IllegalArgumentException("User not found: " + userId);
            }

            var auths = user.authorities() == null ? Collections.<String>emptyList() : user.authorities();
            var authorities = auths.stream()
                    .filter(Objects::nonNull)
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .map(SimpleGrantedAuthority::new)
                    .toList();

            // 4️⃣ 放入SecurityContext
            var authentication = new UsernamePasswordAuthenticationToken(userId, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (ExpiredJwtException e) {
            SecurityContextHolder.clearContext();
            mark(req, AuthErrorCodes.CODE_TOKEN_EXPIRED);

        } catch (JwtException | IllegalArgumentException e) {
            SecurityContextHolder.clearContext();
            mark(req, AuthErrorCodes.CODE_TOKEN_INVALID);
        }

        chain.doFilter(req, res);
    }

    private static void mark(HttpServletRequest req, int code) {
        req.setAttribute(AuthErrorCodes.REQ_ATTR_AUTH_ERROR_CODE, code);
    }
}
