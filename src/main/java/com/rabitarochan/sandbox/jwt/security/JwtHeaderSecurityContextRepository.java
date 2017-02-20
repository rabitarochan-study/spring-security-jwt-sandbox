package com.rabitarochan.sandbox.jwt.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.util.Collection;
import java.util.HashSet;

public class JwtHeaderSecurityContextRepository implements SecurityContextRepository {

    private static final Logger LOG = LoggerFactory.getLogger(JwtHeaderSecurityContextRepository.class);

    private static final String AUTH_HEADER_NAME = "Authorization";

    private static final String AUTH_HEADER_PREFIX = "Bearer ";

    private static final String SECRET = "secret";

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        LOG.info("#### loadContext: " + requestResponseHolder);

        SecurityContext context = getOrCreate();

        String header = getAuthHeader(requestResponseHolder.getRequest());
        if (hasJwtToken(header)) {
            String token = header.substring(AUTH_HEADER_PREFIX.length());

            try {
                JWTVerifier verifier = getJwtVerifier();
                DecodedJWT jwt = verifier.verify(token);

                Collection<GrantedAuthority> authorities =new HashSet<>() ;
                authorities.add(new SimpleGrantedAuthority("ADMIN"));
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(jwt.getSubject(), jwt.getToken(), authorities);

                context.setAuthentication(auth);
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        }

        return context;
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        LOG.info("#### saveContext: " + context);
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        LOG.info("#### containsContext: " + request);
        return true;
    }

    protected String getAuthHeader(HttpServletRequest request) {
        return request.getHeader(AUTH_HEADER_NAME);
    }

    protected boolean hasJwtToken(String header) {
        return (header != null && header.startsWith(AUTH_HEADER_PREFIX));
    }

    protected JWTVerifier getJwtVerifier() throws UnsupportedEncodingException {
        return JWT.require(Algorithm.HMAC256(SECRET)).build();
    }

    protected SecurityContext getOrCreate() {
        SecurityContext context = SecurityContextHolder.getContext();
        if (context == null) {
            context = SecurityContextHolder.createEmptyContext();
        }

        return context;
    }

}
