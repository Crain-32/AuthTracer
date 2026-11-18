package fixtures.permittedqueries;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Decision 0093: the URLs formLogin(..).permitAll() and logout(..).permitAll() let through keep their query string,
 * and the logout URL takes the methods CSRF protection leaves it. Partners log out on any method, to a page only its
 * query string opens; members' logout success URL is their login page's ?logout; staff set a failure URL after a
 * failure handler, and a logout success handler, which permits no URL; guests have a failure handler and a logout
 * matcher of their own.
 */
@Configuration
@EnableWebSecurity
class PermittedQueriesConfig {

    @Bean
    @Order(1)
    SecurityFilterChain partners(HttpSecurity http) throws Exception {
        http.securityMatcher("/partner/**")
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("PARTNER"))
                .logout(logout -> logout.logoutUrl("/partner/logout").logoutSuccessUrl("/partner/home?bye")
                        .permitAll());
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain members(HttpSecurity http) throws Exception {
        http.securityMatcher("/members/**")
                .authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("MEMBER"))
                .formLogin(form -> form.loginPage("/members/signin"))
                .formLogin(form -> form.usernameParameter("member").permitAll(false))
                .logout(logout -> logout.logoutUrl("/members/logout").permitAll());
        return http.build();
    }

    @Bean
    @Order(3)
    SecurityFilterChain staff(HttpSecurity http) throws Exception {
        http.securityMatcher("/staff/**")
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("STAFF"))
                .formLogin(form -> form.loginPage("/staff/signin")
                        .failureHandler(new SimpleUrlAuthenticationFailureHandler("/staff/oops"))
                        .failureUrl("/staff/oops?bad")
                        .permitAll())
                .logout(logout -> logout.logoutUrl("/staff/logout")
                        .logoutSuccessHandler(new SimpleUrlLogoutSuccessHandler())
                        .permitAll());
        return http.build();
    }

    @Bean
    @Order(4)
    SecurityFilterChain guests(HttpSecurity http) throws Exception {
        http.securityMatcher("/guests/**")
                .csrf(Customizer.withDefaults())
                .authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("GUEST"))
                .formLogin(form -> form.failureForwardUrl("/guests/oops").permitAll())
                .logout(logout -> logout.logoutRequestMatcher(PathPatternRequestMatcher.pathPattern(HttpMethod.GET,
                        "/guests/bye")).permitAll());
        return http.build();
    }
}

@Controller
class PagesController {

    @GetMapping("/partner/logout")
    String partnerLogout() {
        return "logout";
    }

    @GetMapping("/partner/home")
    @ResponseBody
    String partnerHome() {
        return "home";
    }

    @GetMapping("/members/signin")
    String memberSignin() {
        return "signin";
    }

    @GetMapping("/members/logout")
    String memberLogout() {
        return "logout";
    }

    @GetMapping("/staff/signin")
    String staffSignin() {
        return "signin";
    }

    @GetMapping("/staff/oops")
    String staffOops() {
        return "oops";
    }

    @GetMapping("/staff/logout")
    String staffLogout() {
        return "logout";
    }

    @GetMapping("/guests/oops")
    String guestOops() {
        return "oops";
    }

    @GetMapping("/guests/bye")
    String guestBye() {
        return "bye";
    }
}
