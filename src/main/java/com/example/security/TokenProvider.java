package com.example.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class TokenProvider {
    // Đoạn JWT_SECRET này là bí mật, chỉ có phía server biết
    private final String JWT_SECRET = "MDE0ZDVkMDYxZTY4YjEzZmU3NTY3NGE0YjA2YTI4ODQ1Yzk0MmZlZDNhMWY4NmM0ZGQyNGRiNGI5ZmIwMTBhYWI5Y2U4YmFjMDMwZTRkYmQzZGI4YTdiMzk1NDNjNGQxY2QxMTc5YTdiOTYyNTAxMmMxOGU3Yjg3NTkyYjIyYzQ=";

    private Logger logger = LoggerFactory.getLogger(getClass());

    //Thời gian có hiệu lực của chuỗi jwt
    private final long JWT_EXPIRATION = 604800000L;

    private final Key key;

    private final JwtParser jwtParser;

    public TokenProvider() {
        byte[] keyBytes = Decoders.BASE64.decode(JWT_SECRET);;
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.jwtParser = Jwts.parserBuilder().setSigningKey(this.key).build();
    }


    // Tạo ra jwt từ thông tin user
    public String generateToken(UserDetails userDetails) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + JWT_EXPIRATION);
        Map<String, Object> claims = new HashMap();

        claims.put("auth",userDetails.getAuthorities());
        claims.put("created", Instant.now().getEpochSecond());
        claims.put("user_id", userDetails.getId());
        claims.put("token_type", "USER");
        // Tạo chuỗi json web token từ id của user.
        return Jwts.builder().setClaims(claims).setSubject(userDetails.getUserName()).setExpiration(expiryDate).signWith(this.key, SignatureAlgorithm.HS512).compact();
    }

    // Lấy thông tin user từ jwt
    public String getUserIdFromJWT(String token) {
        Claims claims = (Claims)this.jwtParser.parseClaimsJws(token).getBody();

        return String.valueOf(claims.get("user_id"));
    }



    public boolean validateToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(JWT_SECRET).parseClaimsJws(authToken);
            return true;
        } catch (ExpiredJwtException ex) {
            logger.error("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            logger.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            logger.error("JWT claims string is empty.");
        }
        return false;
    }

    public Authentication getAuthentication(String token){
        try {
            Claims claims = jwtParser.parseClaimsJws(token).getBody();
            Collection<? extends GrantedAuthority> authorities = Arrays
                    .stream(claims.get("auth").toString().split(","))
                    .filter(auth -> !auth.trim().isEmpty())
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

            IBEUser principal = new IBEUser(claims.getSubject(), "", authorities);

        } catch (Exception e){
            logger.info("Invalid JWT signature: {}", e.getMessage());
        }
    }
}
