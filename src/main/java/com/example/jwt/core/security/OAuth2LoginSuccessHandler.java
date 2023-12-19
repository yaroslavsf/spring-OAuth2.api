package com.example.jwt.core.security;

import com.example.jwt.core.security.helpers.AuthorizationSchemas;
import com.example.jwt.core.security.helpers.JwtProperties;
import com.example.jwt.domain.oauth.CustomOAuth2User;
import com.example.jwt.domain.role.RoleService;
import com.example.jwt.domain.user.Provider;
import com.example.jwt.domain.user.User;
import com.example.jwt.domain.user.UserDetailsImpl;
import com.example.jwt.domain.user.UserService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpHeaders;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.*;

@Component
public class OAuth2LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    @Autowired
    private RestTemplate restTemplate;
    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;
    private final UserService userService;
    private final RoleService roleService;
    @Autowired
    public OAuth2LoginSuccessHandler(UserService userService, RoleService roleService, JwtProperties jwtProperties) {
        this.userService = userService;
        this.roleService = roleService;
        this.jwtProperties = jwtProperties;
    }

    private final JwtProperties jwtProperties;
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws ServletException, IOException {

        OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;

            CustomOAuth2User principal = (CustomOAuth2User) authentication.getPrincipal();
            Map<String, Object> attributes = principal.getAttributes();
            //if email is not public (e.g. in github)
            OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                    oAuth2AuthenticationToken.getAuthorizedClientRegistrationId(),
                    oAuth2AuthenticationToken.getName());
            String email;
            if (attributes.getOrDefault("email", "") == null) {
               email = fetchUserEmail(authorizedClient.getAccessToken().getTokenValue());
            } else {
                email = attributes.getOrDefault("email", "").toString();
            }
            String name = attributes.getOrDefault("name", "").toString();
            userService.findByEmail(email)
                    .ifPresentOrElse(user -> {
                        if (!user.getProvider().provider.equals(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId())) {
                            throw new RuntimeException("User with this email is already signed up with different service");
                        }
                        //conditional id/sub
                        DefaultOAuth2User newUser =
                                new DefaultOAuth2User(List.of(new SimpleGrantedAuthority(user.getRoles().toString())),
                                attributes, ("github".equals(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId())) ? "id" : "sub");
                        Authentication securityAuth =
                                new OAuth2AuthenticationToken(newUser, List.of(new SimpleGrantedAuthority(user.getRoles().toString())),
                                oAuth2AuthenticationToken.getAuthorizedClientRegistrationId());
                        SecurityContextHolder.getContext().setAuthentication(securityAuth);

                        response.addHeader(HttpHeaders.AUTHORIZATION, AuthorizationSchemas.BEARER + " " + generateToken(user));
                    }, () -> {
                        //user register
                        User userEntity = new User();
                        userEntity.setRoles(Set.of(roleService.findByName("USER")));
                        userEntity.setEmail(email);
                        String[] splited = name.split("\\s+");
                        userEntity.setFirstName(splited[0]);
                        userEntity.setLastName(splited[1]);
                        userEntity.setCreatedAt(LocalDateTime.now());
                        userEntity.setProvider(("github".equals(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId())) ? Provider.GITHUB : Provider.GOOGLE);
                        User user = userService.save(userEntity);
                        //conditional id/sub
                        DefaultOAuth2User newUser = new DefaultOAuth2User(List.of(new SimpleGrantedAuthority(userEntity.getRoles().toString())),
                                attributes, ("github".equals(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId())) ? "id" : "sub");
                        Authentication securityAuth = new OAuth2AuthenticationToken(newUser, List.of(new SimpleGrantedAuthority(userEntity.getRoles().toString())),
                                oAuth2AuthenticationToken.getAuthorizedClientRegistrationId());
                        SecurityContextHolder.getContext().setAuthentication(securityAuth);
                        response.addHeader(HttpHeaders.AUTHORIZATION, AuthorizationSchemas.BEARER + " " + generateToken(user));
                    });

        this.setAlwaysUseDefaultTargetUrl(false);
        super.onAuthenticationSuccess(request, response, authentication);
    }

    private String generateToken(User user) {
        UserDetailsImpl userDetails = new UserDetailsImpl(user);
        SecurityContextHolder.getContext()
                .setAuthentication(new UsernamePasswordAuthenticationToken(userDetails, null,
                        userDetails.getAuthorities()));

        byte[] keyBytes = Decoders.BASE64.decode(jwtProperties.getSecret());

        return Jwts.builder()
                .setClaims(Map.of("sub", userDetails.user()
                        .getId(), "authorities", userDetails.getAuthorities()))
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtProperties.getExpirationMillis()))
                .setIssuer(jwtProperties.getIssuer())
                .signWith(Keys.hmacShaKeyFor(keyBytes))
                .compact();
    }

    //for github email if its hidden by default
    private String fetchUserEmail(String accessToken) {
        String apiUrl = "https://api.github.com/user/emails";
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        HttpEntity<String> entity = new HttpEntity<>(headers);
        try {
            ResponseEntity<String> response = restTemplate.exchange(apiUrl, HttpMethod.GET, entity, String.class);
            if (response.getStatusCode() == HttpStatus.OK) {
                String body = response.getBody();
                JSONArray emailsArray = new JSONArray(response.getBody());
               // Find the primary email
                for (int i = 0; i < emailsArray.length(); i++) {
                    JSONObject emailObject = emailsArray.getJSONObject(i);
                    boolean isPrimary = emailObject.getBoolean("primary");
                    if (isPrimary) {
                        return emailObject.getString("email");
                    }
                }
            }
        } catch (RestClientException e) {
            //handle exception
        }
        return null; // Handle the case where email is not found or there's an error
    }
}