package com.luv2code.springboot.cruddemo.security;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration

public class DemoSecuConfig {

	//add support for JDBC.. no more hard coded users 
	//linked with the tables we created in the SQL DB : users + authorities (NAME SHOULD BE STRICTLY THE SAME) !!!
	
	@Bean
	public UserDetailsManager userDetailsManager(DataSource dataSource) {
		
		// for using custom tables  
		
		JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
		
		//define query to retrieve a user by user name
		
		jdbcUserDetailsManager.setUsersByUsernameQuery(
				
		// "?" means parameters value will be the user name from login ( users id, password etc...)
				
				"SELECT user_id, pw, active from members where user_id=?"
				
				);
		
		//define query to retrieve the authorities / roles by user name
		jdbcUserDetailsManager.setAuthoritiesByUsernameQuery(
				"SELECT user_id, role from roles where user_id=?"
				);
		
		return  jdbcUserDetailsManager;
	}
	
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
		http.authorizeHttpRequests(configurer ->
		configurer
			.requestMatchers(HttpMethod.GET,"/api/employees").hasRole("EMPLOYEE")
			.requestMatchers(HttpMethod.GET,"/api/employees/**").hasRole("EMPLOYEE")
			.requestMatchers(HttpMethod.POST,"/api/employees").hasRole("MANAGER")
			.requestMatchers(HttpMethod.PUT,"/api/employees").hasRole("MANAGER")
			.requestMatchers(HttpMethod.DELETE,"/api/employees/**").hasRole("ADMIN")
				);
		//use HTTP basic authentication
		http.httpBasic();
		
		//disable CSRF
		//in general, not required for stateless REST APIs that use POST PUT DELETE and PATCH
		
		http.csrf().disable();
		
		return http.build();
	}
	
	/*
	@Bean
	public InMemoryUserDetailsManager userDetailsManager() {
		
		UserDetails john = User.builder()
				.username("John")
				.password("{noop}test123")
				.roles("EMPLOYEE")
				.build();
		UserDetails mary = User.builder()
				.username("Mary")
				.password("{noop}test123")
				.roles("EMPLOYEE","MANAGER")
				.build();
		UserDetails susan = User.builder()
				.username("Susan")
				.password("{noop}test123")
				.roles("EMPLOYEE","MANAGER","ADMIN")
				.build();
		UserDetails liang = User.builder()
				.username("Liang")
				.password("{noop}123456")
				.roles("EMPLOYEE","MANAGER","ADMIN")
				.build();
		return new InMemoryUserDetailsManager(john, mary, susan,liang);
	}
	*/

}