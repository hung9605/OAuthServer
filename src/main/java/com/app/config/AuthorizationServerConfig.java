package com.app.config;

import java.time.Duration;
import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.session.data.redis.RedisIndexedSessionRepository;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class AuthorizationServerConfig {
	
	@Value("${issuer}")
	private String issuer;
	
	@Value("${redirect.uri}")
	private String redirectUri;
	
	@Autowired
	private RedisIndexedSessionRepository sessionRepository;
	

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
    	TokenSettings tokenSettings = TokenSettings.builder()
    		    .accessTokenTimeToLive(Duration.ofMinutes(30))
    		    .refreshTokenTimeToLive(Duration.ofHours(12))
    		    .build();
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(redirectUri)
                .postLogoutRedirectUri("http://localhost:4200")
                //.redirectUri("https://oauth.pstmn.io/v1/callback")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .scope("read")
                .tokenSettings(tokenSettings)
                .build();
                return new InMemoryRegisteredClientRepository(registeredClient);
    }
    

  @Bean("authServerFilterChain")
  @Order(1)
public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
            new OAuth2AuthorizationServerConfigurer();
    authorizationServerConfigurer
            .tokenRevocationEndpoint(Customizer.withDefaults())
            .oidc(Customizer.withDefaults());                
    http
        .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
        .authorizeHttpRequests(authorize -> authorize
        		.requestMatchers("/oauth2/logout-rp", "/connect/logout").permitAll()
        		.anyRequest().authenticated())
        .with(authorizationServerConfigurer, Customizer.withDefaults())
        .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
        .formLogin(Customizer.withDefaults());

    return http.build();
}


@Bean
@Order(2)
public SecurityFilterChain defaultFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(authorize -> authorize
    		.requestMatchers(HttpMethod.GET,"/oauth2/logout-rp").permitAll()
    		.anyRequest().authenticated())
    .oauth2ResourceServer(oauth2 -> oauth2
            .jwt(Customizer.withDefaults()) // bật xác thực JWT
        )
//    .logout(logout -> logout
//    		.logoutUrl("/connect/logout") 
//    		   .addLogoutHandler((request, response, authentication) -> {
//    		        if (request.getSession(false) != null) {
//    		        	System.out.println("sesion logout : " + request.getSession().getId());
//    		            sessionRepository.deleteById(request.getSession().getId());
//    		        }
//    		    })
//           
//            .logoutSuccessUrl("/login?logout") // Trang redirect sau logout
//            .invalidateHttpSession(true)
//            .clearAuthentication(true)
//            .deleteCookies("JSESSIONID")
//        )
            .formLogin(Customizer.withDefaults());
    return http.build();
}
    
 
    
    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = Jwks.generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }
    
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(issuer)
                .build();
    }
    
    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository clientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, clientRepository);
    }
    


}