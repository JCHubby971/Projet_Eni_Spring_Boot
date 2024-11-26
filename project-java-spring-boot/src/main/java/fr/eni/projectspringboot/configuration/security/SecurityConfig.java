package fr.eni.projectspringboot.configuration.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final String SELECT_USER = "SELECT pseudo, mot_de_passe AS password, 1 FROM UTILISATEURS WHERE " +
            "pseudo=?";
    private static final String SELECT_ROLE = "SELECT u.email, r.ROLE from UTILISATEURS as u INNER JOIN ROLES as r " +
            "ON u.administrateur = r.IS_ADMIN WHERE u.pseudo=?";


    @Bean
    UserDetailsManager userDetailsManager(DataSource dataSource) {
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.setUsersByUsernameQuery(SELECT_USER);
        jdbcUserDetailsManager.setAuthoritiesByUsernameQuery(SELECT_ROLE);
        return jdbcUserDetailsManager;
    }

/*
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authz -> authz
                                           .requestMatchers("/public/**").permitAll()
                                           .requestMatchers("/admin/**").hasRole("ADMIN")
                                           .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")
                                           .anyRequest().authenticated()
                                  )
            .formLogin(form -> form
                               .loginPage("/login")
                               .permitAll()
                      )
            .logout(logout -> logout
                    .logoutSuccessUrl("/login?logout")
                    .permitAll()
                   );
        return http.build();
    }
*/
}
