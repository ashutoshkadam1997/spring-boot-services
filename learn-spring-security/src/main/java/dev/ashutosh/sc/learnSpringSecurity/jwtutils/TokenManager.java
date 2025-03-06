package dev.ashutosh.sc.learnSpringSecurity.jwtutils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * This class will be responsible for the creation and validation of tokens using io.jsonwebtoken.Jwts.
 */
@Component
public class TokenManager {

    public static final long TOKEN_VALIDITY = 10 * 60 * 60;

    @Value("${secret}")
    private String jwtSecret;

    /**
     * @Description : Generates a token on successful authentication by the user using username, issue date of token and the expiration date of the token.
     * @param userDetails
     * @return
     */
    public String generateJwtToken(UserDetails userDetails){
        Map<String, Object> claims = new HashMap<>();
        return Jwts
                .builder()
                .setClaims(claims)  // set the claims
                .setSubject(userDetails.getUsername())  // set the username as subject in payload
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + TOKEN_VALIDITY * 1000))
                .signWith(getKey(), SignatureAlgorithm.HS256)  // signature part
                .compact();
    }

    /**
     * create a signing key based on secret
     * @return
     */
    private Key getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        Key key = Keys.hmacShaKeyFor(keyBytes);
        return key;
    }


    /**
     * Validates the token
     * Checks if user is an authentic one and using the token is the one that was generated and sent to the user.
     * Token is parsed for the claims such as username, roles, authorities, validity period etc.
     * @param token
     * @param userDetails
     * @return
     */
    public Boolean validateJwtToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        final Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token).getBody();
        Boolean isTokenExpired = claims.getExpiration().before(new Date());
        return (username.equals(userDetails.getUsername())) && !isTokenExpired;
    }

    /**
     * get the username by checking subject of JWT Token
     * @param token
     * @return
     */
    public String getUsernameFromToken(String token) {
        final Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token).getBody();
        return claims.getSubject();
    }
}
