package org.springframework.cloud.config.server.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.micrometer.core.instrument.util.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

	private static Log logger = LogFactory.getLog(JwtAuthorizationFilter.class);

	public JwtAuthorizationFilter(AuthenticationManager authenticationManager) {
		super(authenticationManager);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
		// Read the Authorization header, where the JWT token should be
		String header = request.getHeader(JwtProperties.HEADER_STRING);

		// If header does not contain BEARER or is null delegate to Spring impl and exit
		if (header == null || !header.startsWith(JwtProperties.TOKEN_PREFIX)) {
			chain.doFilter(request, response);
			return;
		}

		// If header is present, try grab user principal from database and perform authorization
		Authentication authentication = getUsernamePasswordAuthentication(request);
		SecurityContextHolder.getContext().setAuthentication(authentication);

		// Continue filter execution
		chain.doFilter(request, response);
	}

	private Authentication getUsernamePasswordAuthentication(HttpServletRequest request) {
		String token = request.getHeader(JwtProperties.HEADER_STRING)
			.replace(JwtProperties.TOKEN_PREFIX,"");

		if (token == null) {
			logger.warn("Token not provided");
			return null;
		}

		// parse the token and validate it
		DecodedJWT decodedJwt = JWT.require(HMAC512(JwtProperties.SECRET.getBytes()))
			.build()
			.verify(token);

		String username = decodedJwt.getSubject();
		if (StringUtils.isBlank(username)) {
			logger.warn("Username is blank");
			return null;
		}

		Claim claim = decodedJwt.getClaim("scope");
		if (claim == null) {
			logger.warn("Scope not provided");
			return null;
		}

		String scope = claim.asString();
		if (StringUtils.isBlank(scope)) {
			logger.warn("Scope is blank");
			return null;
		}

		ConfigUserPrincipal principal = new ConfigUserPrincipal(username, scope.split(","));
		UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, null, principal.getAuthorities());
		return auth;
	}
}
