package com.app.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    /* Sin anotaciones*/
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
//
//        return httpSecurity
//                .csrf(AbstractHttpConfigurer::disable)
//                .httpBasic(Customizer.withDefaults())
//                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                .authorizeHttpRequests(http -> {
//                    /* Endpoints publicos */
//                    http.requestMatchers(HttpMethod.GET, "auth/hello").permitAll();
//                    /* Endpoints privados */
//                    http.requestMatchers(HttpMethod.GET, "auth/hello-secured").hasAuthority("READ");
//                    /* El resto */
//                    http.anyRequest().denyAll();
//                })
//                .build();
//    }

    /* Con anotaciones */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        return httpSecurity
                .csrf(csrf -> csrf.disable())
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(http -> {
                    /* Endpoints publicos */
                    http.requestMatchers(HttpMethod.GET, "auth/get").permitAll();
                    /* Endpoints privados */
                    http.requestMatchers(HttpMethod.POST, "auth/post").hasAnyAuthority("READ", "CREATE");
                    http.requestMatchers(HttpMethod.PATCH, "auth/patch").hasAuthority("CREATE");
                    http.requestMatchers(HttpMethod.DELETE, "auth/delete").hasAnyRole("ADMIN","DEVELOPER");
                    http.requestMatchers(HttpMethod.PUT, "auth/put").hasRole("ADMIN");

                    /* El resto */
                    http.anyRequest().denyAll();
                })
                .build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfig) throws Exception {
        return authenticationConfig.getAuthenticationManager();
    }

    @Bean
    public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService) throws Exception {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder());
        provider.setUserDetailsService(userDetailsService);
        return provider;
    }

    public UserDetailsService userDetailsService() {
        List<UserDetails> userDetailsListI = new ArrayList<>();

        userDetailsListI.add(
                User.withUsername("admin")
                        .password("12345")
                        .roles("ADMIN")
                        .authorities("READ","CREATE")
                        .build()
        );

        userDetailsListI.add(
                User.withUsername("admin2")
                        .password("12345")
                        .roles("ADMIN")
                        .authorities("READ")
                        .build()
        );


        return new InMemoryUserDetailsManager(userDetailsListI);
    }

    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
