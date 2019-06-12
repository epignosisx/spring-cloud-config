package org.springframework.cloud.config.server.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;

public class CustomRequestMatcher implements RequestMatcher {

	@Override
	public boolean matches(HttpServletRequest httpServletRequest) {
		String pathAndQuery = httpServletRequest.getRequestURI();
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth == null || !auth.isAuthenticated()) {
			return false;
		}

		for (GrantedAuthority authority : auth.getAuthorities()) {
			String allowedUri = authority.getAuthority();
			if (allowedUri.equalsIgnoreCase(pathAndQuery)) {
				return true;
			}
		}

		return false;
	}
}
