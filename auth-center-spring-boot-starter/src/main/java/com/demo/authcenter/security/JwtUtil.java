package com.demo.authcenter.security;

import com.demo.authcenter.properties.JwtProps;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

/**
 * JWT 工具
 * <p>
 * 功能：负责 token 的签发、解析与基础校验
 * <p>
 * 参数：
 * - jti = 唯一标识
 * - iss = 签发者
 * - sub = 主题
 * - aud = 接收方
 * - type = 类型 access /refresh
 * - iat = 签发时间
 * - exp = 过期时间
 * - nbf = 生效时间
 * <p>
 * 约定：
 * - sub = userId
 * - jti = token 唯一标识（用于登出/黑名单）
 * - typ = "access" | "refresh"
 * - aud 写入 claim "aud"（List<String>），并兼容不同 JWT 版本的 audience 返回类型
 * <p>
 * 说明：黑名单、登出、刷新轮换不在此类处理，由 TokenStore/Service 负责。
 */
public class JwtUtil {

    public static final String CLAIM_TYP = "typ";
    public static final String TYP_ACCESS = "access";
    public static final String TYP_REFRESH = "refresh";
    public static final String CLAIM_USERNAME = "username";
    public static final String CLAIM_ROLES = "roles";
    public static final String CLAIM_AUD = "aud";

    private final JwtProps jwtProps;
    private final SecretKey key;

    public JwtUtil(JwtProps jwtProps) {
        this.jwtProps = Objects.requireNonNull(jwtProps, "jwtProps must not be null");
        validateProps(jwtProps);
        this.key = initKey(jwtProps.getSecret());
    }


    // =========================
    // 生成 Token
    // =========================

    /**
     * 生成 Access Token（iss/aud/jti/typ=access，sub=userId）
     */
    public String generateAccessToken(Long userId, String username, Collection<String> roles) {
        return buildToken(userId, username, roles, TYP_ACCESS, jwtProps.getAccessTtlSeconds());
    }

    /**
     * 生成 Refresh Token（iss/aud/jti/typ=refresh，sub=userId）
     */
    public String generateRefreshToken(Long userId) {
        if (!jwtProps.isRefreshEnabled()) {
            throw new IllegalStateException("refresh is disabled by auth.jwt.refresh-enabled=false");
        }
        return buildToken(userId, null, null, TYP_REFRESH, jwtProps.getRefreshTtlSeconds());
    }

    /**
     * 生成token
     */
    private String buildToken(Long userId,
                              String username,
                              Collection<String> roles,
                              String typ,
                              long ttlSeconds) {
        if (userId == null) throw new IllegalArgumentException("userId must not be null");
        if (ttlSeconds <= 0) throw new IllegalArgumentException("ttlSeconds must be > 0");

        Instant now = Instant.now();
        String jti = UUID.randomUUID().toString();

        // aud 直接写入 payload claim，避免不同 JJWT 版本 audience builder 行为差异
        List<String> audList = new ArrayList<>(jwtProps.getAudience());

        var builder = Jwts.builder()
                .id(jti)                                                // jti
                .issuer(jwtProps.getIssuer())                           // iss
                .subject(String.valueOf(userId))                        // sub=userId
                .claim(CLAIM_AUD, audList)                              // aud (list)
                .claim(CLAIM_TYP, typ)                                  // typ
                .issuedAt(Date.from(now))                               // iat
                .expiration(Date.from(now.plusSeconds(ttlSeconds)))     // exp
                .signWith(key);

        // access 才放业务信息；refresh 尽量“瘦”
        if (StringUtils.hasText(username)) {
            builder.claim(CLAIM_USERNAME, username);
        }
        if (roles != null && !roles.isEmpty()) {
            builder.claim(CLAIM_ROLES, new ArrayList<>(roles));
        }

        return builder.compact();
    }

    // =========================
    // 解析 + 基础校验
    // =========================

    /**
     * 解析并校验签名、exp、iss（aud/typ 由调用方按需校验）
     */
    public Claims parseAndValidate(String token) {
        if (!StringUtils.hasText(token)) {
            throw new IllegalArgumentException("Token is blank");
        }
        try {
            Jws<Claims> jws = Jwts.parser()
                    .verifyWith(key)
                    .requireIssuer(jwtProps.getIssuer())
                    .clockSkewSeconds(jwtProps.getClockSkewSeconds())
                    .build()
                    .parseSignedClaims(token);
            return jws.getPayload();
        } catch (JwtException e) {
            throw new IllegalArgumentException("Invalid JWT", e);
        }
    }

    /**
     * 校验接收方aud
     */
    public void validateAudience(Claims claims) {
        List<String> allowed = jwtProps.getAudience();
        if (allowed == null || allowed.isEmpty()) {
            // props 校验已保证非空；这里兜底避免未来被错误配置时“全拒绝”难排查
            return;
        }

        List<String> tokenAud = extractAudience(claims);
        boolean ok = tokenAud.stream().anyMatch(allowed::contains);
        if (!ok) {
            throw new IllegalArgumentException("Invalid audience");
        }
    }

    /**
     * 校验 typ=access
     */
    public void validateAccessType(Claims claims) {
        validateType(claims, TYP_ACCESS);
    }

    /**
     * 校验 typ=refresh
     */
    public void validateRefreshType(Claims claims) {
        validateType(claims, TYP_REFRESH);
    }

    private void validateType(Claims claims, String expected) {
        String typ = claims.get(CLAIM_TYP, String.class);
        if (!expected.equals(typ)) {
            throw new IllegalArgumentException("Token type is not " + expected);
        }
    }

    /**
     * 取 jti（用于黑名单/登出）
     */
    public String getJti(Claims claims) {
        return claims.getId();
    }

    /**
     * 取 userId（sub）
     */
    public Long getUserId(Claims claims) {
        String sub = claims.getSubject();
        if (!StringUtils.hasText(sub)) return null;
        try {
            return Long.valueOf(sub);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * 从 Header 提取 token。
     * - 兼容大小写：bearer/Bearer
     * - 兼容多空格：Bearer    xxx
     */
    public String extractBearerToken(String authorizationHeader) {
        if (!StringUtils.hasText(authorizationHeader)) return null;

        String h = authorizationHeader.trim();
        String prefix = "Bearer";
        if (!h.regionMatches(true, 0, prefix, 0, prefix.length())) {
            return null;
        }

        String rest = h.substring(prefix.length()).trim();
        if (rest.startsWith(":")) { // 极少数网关会写成 Bearer:xxx
            rest = rest.substring(1).trim();
        }
        return rest.isEmpty() ? null : rest;
    }

    // =========================
    // 内部辅助方法
    // =========================
    private void validateProps(JwtProps props) {
        if (!StringUtils.hasText(props.getIssuer())) {
            throw new IllegalArgumentException("auth.jwt.issuer must not be blank");
        }
        if (props.getAudience() == null || props.getAudience().isEmpty()) {
            throw new IllegalArgumentException("auth.jwt.audience must not be empty");
        }
        if (props.getAccessTtlSeconds() <= 0) {
            throw new IllegalArgumentException("auth.jwt.access-ttl-seconds must be > 0");
        }
        if (props.isRefreshEnabled() && props.getRefreshTtlSeconds() <= 0) {
            throw new IllegalArgumentException("auth.jwt.refresh-ttl-seconds must be > 0 when refresh enabled");
        }
        if (props.getClockSkewSeconds() < 0) {
            throw new IllegalArgumentException("auth.jwt.clock-skew-seconds must be >= 0");
        }
        if (!StringUtils.hasText(props.getSecret())) {
            throw new IllegalArgumentException("auth.jwt.secret must not be blank");
        }
    }

    private SecretKey initKey(String secret) {
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        // HS256 推荐至少 32 bytes；不足会导致运行期异常或安全性差
        if (bytes.length < 32) {
            throw new IllegalArgumentException("auth.jwt.secret length must be at least 32 bytes for HS256");
        }
        return Keys.hmacShaKeyFor(bytes);
    }

    /**
     * 提取接收方
     *
     * @param claims
     * @return
     */
    private List<String> extractAudience(Claims claims) {
        // 1) 先尝试标准 API（不同版本可能返回 String / Set / Collection）
        Object standardAudObj;
        try {
            standardAudObj = claims.getAudience();
        } catch (Exception e) {
            standardAudObj = null;
        }

        List<String> fromStandard = normalizeAudienceObject(standardAudObj);
        if (!fromStandard.isEmpty()) return fromStandard;

        // 2) 再从 claim map 取 aud（本工具写入的是这个）
        Object aud = claims.get(CLAIM_AUD);
        return normalizeAudienceObject(aud);
    }

    private List<String> normalizeAudienceObject(Object audObj) {
        if (audObj == null) return List.of();

        if (audObj instanceof String s) {
            return StringUtils.hasText(s) ? List.of(s) : List.of();
        }
        if (audObj instanceof Collection<?> c) {
            if (c.isEmpty()) return List.of();
            List<String> list = new ArrayList<>();
            for (Object x : c) {
                if (x == null) continue;
                String v = String.valueOf(x);
                if (StringUtils.hasText(v)) list.add(v);
            }
            return list;
        }

        // 兜底：转字符串
        String v = String.valueOf(audObj);
        return StringUtils.hasText(v) ? List.of(v) : List.of();
    }


}
