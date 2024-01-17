package com.example.demo.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

//import admin_user.service.CustomSuccessHandler;
//import admin_user.service.CustomUserDetailsService;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	
	@Autowired
	CustomSuccessHandler customSuccessHandler;
	
	@Autowired
	CustomUserDetailsService customUserDetailsService;
	
	@Bean
	public static PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	
	
//	@Bean
//	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//	    http.csrf(c -> c.disable())
//
//	        .authorizeHttpRequests(authorize -> authorize
//	            .requestMatchers(AntPathRequestMatcher("/adminHome")).hasAuthority("ADMIN")
//	            .requestMatchers(AntPathRequestMatcher("/userHome")).hasAuthority("USER")
//	            .requestMatchers(AntPathRequestMatcher("/registration", "/css/**")).permitAll()
//	            .requestMatchers(AntPathRequestMatcher("/userLogin")).permitAll()
//	            .requestMatchers(AntPathRequestMatcher("/services/**"))  // Assuming services are handled by MessageDispatcherServlet
//	                .authorizeRequests()
//	                // ... (configure security for services)
//	            .anyRequest().authenticated()
//	        )
//
//	        .formLogin(form -> form.loginPage("/userLogin").loginProcessingUrl("/userLogin")
//	                .successHandler(customSuccessHandler).permitAll())
//
//	        .logout(form -> form.invalidateHttpSession(true).clearAuthentication(true)
//	                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
//	                .logoutSuccessUrl("/login?logout").permitAll());
//
//	    return http.build();
//	}
	
	
	
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

	    http.csrf(c -> c.disable())

	        .authorizeHttpRequests(request -> request
	        	.requestMatchers("/admin/static/css/**", "/admin/static/plugins/**", "/admin/static/js/**", "/admin/static/images/**",  "/admin/static/webjars/**").permitAll()
	            .requestMatchers("/static/css/assets/**","static/css/vendors/**").permitAll()
	        	.requestMatchers("/adminHome").hasAuthority("ADMIN")
	            .requestMatchers("/userHome").hasAuthority("USER")
	            .requestMatchers("/", "/userLogin", "/logout", "/register", "/sendOTP/{email}").permitAll()  // Allow public access for login and logout
	            // .requestMatchers("/viewProfileDetail").hasAuthority("ADMIN")  // Allow admins to access viewProfileDetail
	            //.requestMatchers("/admin/static/**").permitAll()  // Allow access to static resources under /admin/static/**
	            .anyRequest().authenticated())  // Require authentication for all other requests

	        .formLogin(form -> form
	            .loginPage("/userLogin").loginProcessingUrl("/userLogin")
	            .successHandler(new CustomSuccessHandler()).permitAll())

	        .logout(form -> form
	            .invalidateHttpSession(true).clearAuthentication(true)
	            .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
	            .logoutSuccessUrl("/userLogin?logout").permitAll());

	    return http.build();
	}

	
	
	
	
	
//	@Bean
//	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//
//	    http.csrf(c -> c.disable())
//
//	        .authorizeHttpRequests(request -> request
//	            .requestMatchers("/adminHome").hasAuthority("ADMIN")
//	            .requestMatchers("/userHome").hasAuthority("USER")
//	            .requestMatchers("/", "/userLogin", "/logout", "/register", "/sendOTP/{email}").permitAll()  // Allow public access for login and logout
//	           // .requestMatchers("/viewProfileDetail").hasAuthority("ADMIN")  // Allow admins to access viewProfileDetail
//	            .anyRequest().authenticated())  // Require authentication for all other requests
//
//	        .formLogin(form -> form
//	            .loginPage("/userLogin").loginProcessingUrl("/userLogin")
//	            .successHandler(new CustomSuccessHandler()).permitAll())
//
//	        .logout(form -> form
//	            .invalidateHttpSession(true).clearAuthentication(true)
//	            .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
//	            .logoutSuccessUrl("/userLogin?logout").permitAll());
//
//	    return http.build();
//	}


	
	
	
	
	
//	 @Bean public SecurityFilterChain securityFilterChain(HttpSecurity http)
//			  throws Exception{
//			  
//			  http.csrf(c -> c.disable())
//			  
//			  .authorizeHttpRequests(request -> request.requestMatchers("/adminHome")
//			  .hasAuthority("ADMIN").requestMatchers("/userHome").hasAuthority("USER")
//			  .requestMatchers("/").permitAll()
//			  .anyRequest().authenticated())
//			  
//			  
//			 .formLogin(form ->
//			  form.loginPage("/userLogin").loginProcessingUrl("/userLogin")
//			  .successHandler( new CustomSuccessHandler()).permitAll())
//			  
//			  .logout(form -> form.invalidateHttpSession(true).clearAuthentication(true)
//			  .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
//			  .logoutSuccessUrl("/userLogin?logout").permitAll());
//			  
//			  return http.build();
//			  
//			  }
	 
	
	
	
//	@Bean
//	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//	    http
//	        .csrf(c -> c.disable())
//
//	        .requestMatchers(MvcRequestMatcher.mvcMatchers("/admin-page", "/user-page", "/registration"))
//	            .authorizeRequests()
//	            .antMatchers("/admin-page").hasAuthority("ADMIN")
//	            .antMatchers("/user-page").hasAuthority("USER")
//	            .antMatchers("/registration", "/css/**").permitAll()
//	            .anyRequest().authenticated()
//
//	        .formLogin(form -> form.loginPage("/login").loginProcessingUrl("/login")
//	            .successHandler(customSuccessHandler).permitAll())
//
//	        .logout(form -> form.invalidateHttpSession(true).clearAuthentication(true)
//	            .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
//	            .logoutSuccessUrl("/login?logout").permitAll());
//
//	    return http.build();
//	}

	
	@Autowired
	public void configure (AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(customUserDetailsService).passwordEncoder(passwordEncoder());
	}

}
