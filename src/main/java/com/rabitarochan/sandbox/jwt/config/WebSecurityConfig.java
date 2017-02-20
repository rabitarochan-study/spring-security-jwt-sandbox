package com.rabitarochan.sandbox.jwt.config;

import com.rabitarochan.sandbox.jwt.security.JwtAuthenticationEntryPoint;
import com.rabitarochan.sandbox.jwt.security.JwtAuthenticationFilter;
import com.rabitarochan.sandbox.jwt.security.JwtHeaderSecurityContextRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * Spring Security settings.
 */
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Value("${app.auth.ldap.host}")
    private String authAdLdapServerDomain;

    @Value("${app.auth.ldap.url}")
    private String authAdLdapServerUrl;

    @Value("${app.auth.ldap.rootdn}")
    private String authAdLdapServerRootDn;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("admin").password("secret").roles("ADMIN");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);

        http.csrf().disable();

        http.authorizeRequests()
                .antMatchers("/api/login").permitAll();

        // Don't redirect to login page when not authenticated.
        http.exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint());

        http.securityContext()
                .securityContextRepository(jwtHeaderSecurityContextRepository());

        http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        http.authenticationProvider(adAuthenticationProvider());
    }

    @Bean
    public AuthenticationEntryPoint jwtAuthenticationEntryPoint() {
        return new JwtAuthenticationEntryPoint();
    }

    @Bean
    public SecurityContextRepository jwtHeaderSecurityContextRepository() {
        return new JwtHeaderSecurityContextRepository();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter("/api/login", authenticationManager);
    }

    @Bean
    public AuthenticationProvider adAuthenticationProvider() {
        ActiveDirectoryLdapAuthenticationProvider provider =
                new ActiveDirectoryLdapAuthenticationProvider(authAdLdapServerDomain, authAdLdapServerUrl, authAdLdapServerRootDn);

        return provider;
    }

}
