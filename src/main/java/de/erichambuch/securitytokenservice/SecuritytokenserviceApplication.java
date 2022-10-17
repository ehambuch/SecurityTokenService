package de.erichambuch.securitytokenservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.metrics.web.servlet.WebMvcMetricsAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;

/**
 * Main Spring Boot application.
 * <p>Although we are using Spring Boot, we disable certain auto configurations.</p>
 */
@SpringBootApplication(exclude = {WebMvcMetricsAutoConfiguration.class, SecurityAutoConfiguration.class, ManagementWebSecurityAutoConfiguration.class, UserDetailsServiceAutoConfiguration.class})
public class SecuritytokenserviceApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecuritytokenserviceApplication.class, args);
	}

}
