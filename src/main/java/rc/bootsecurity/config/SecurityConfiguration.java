package rc.bootsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        auth
                .inMemoryAuthentication()
                .withUser("admin")
                .password(passwordEncoder().encode("admin"))
                .roles("ADMIN").authorities("ACCESS_TEST1", "ACCESS_TEST2")
                .and()
                .withUser("dmitry")
                .password(passwordEncoder().encode("koryanov"))
                .roles("USER")
                .and()
                .withUser("manager")
                .password(passwordEncoder().encode("manager"))
                .roles("MANAGER").authorities("ACCESS_TEST1");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/profile/**").authenticated()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/management/**").hasAnyRole("ADMIN","MANAGER")
                .antMatchers("/api/public/test1").hasAuthority("ACCESS_TEST1")
                .antMatchers("/api/public/test2").hasAuthority("ACCESS_TEST2")
                .antMatchers("/api/public/users").hasRole("ADMIN")
                //.antMatchers("/**").permitAll()
                //.anyRequest()
                //.authenticated()
                .and()
                .httpBasic();
                /*.and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/index");*/
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
