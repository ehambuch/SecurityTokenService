package de.erichambuch.securitytokenservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.metrics.web.servlet.WebMvcMetricsAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

// TODO: besser Spring als Spring Boot nutzen, um minimale Konfig zu machen
@SpringBootApplication(exclude = {WebMvcMetricsAutoConfiguration.class, SecurityAutoConfiguration.class, ManagementWebSecurityAutoConfiguration.class})
public class SecuritytokenserviceApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecuritytokenserviceApplication.class, args);
	}

}
