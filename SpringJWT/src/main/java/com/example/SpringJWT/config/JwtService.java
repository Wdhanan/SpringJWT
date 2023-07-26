package com.example.SpringJWT.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

 private static final String SECRET_KEY="kWITS4Z8DW4Op4kT1M/kt8i8PKjBnHS63zn+RDHj0IoYYBQnsNfDb2pSrHqk/XSi";// generated
    // from the Website "Generate Random"
    public String extractUsername(String token) {// get the username using token
        return extractClaim(token, Claims:: getSubject);// implementation
    }
    //method to extract a single claim
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);

    }


    //method to extract all the claims
    private Claims extractAllClaims(String token){// to extract all claims
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey()) // to decode a Token to verify the sender is who he claims to be, we need to generate a secret key
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte [] keyBytes = Decoders.BASE64.decode(SECRET_KEY);// decode our secret key
        return Keys.hmacShaKeyFor(keyBytes);
    }

    //method to generate Token only from UserDetails without needing ExtraClaims

    public String generateToken( UserDetails userDetails){
        return generateToken( new HashMap<>(), userDetails);
    }

    // method to generate a Token
    public String generateToken(
            Map<String, Object> extraClaims, UserDetails userDetails
    ){
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt( new Date (System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000*60*24))// Token is valid for 24 Hours
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();// generate and return the Token
    }

    // method to validate a Token
    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }


    // make sure the token is not Expired
    private boolean isTokenExpired(String token) {
        return  extractExpiration(token).before(new  Date());
    }
    // get the Expiration Date of a Token
    private Date extractExpiration (String token){
        return extractClaim(token, Claims::getExpiration);
    }
}
