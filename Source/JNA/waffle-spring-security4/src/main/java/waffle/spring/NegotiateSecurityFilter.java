/**
 * Waffle (https://github.com/dblock/waffle)
 *
 * Copyright (c) 2010 - 2015 Application Security, Inc.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     Application Security, Inc.
 */
package waffle.spring;

import java.io.IOException;
import java.util.Locale;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import waffle.servlet.WindowsPrincipal;
import waffle.servlet.spi.SecurityFilterProviderCollection;
import waffle.util.AuthorizationHeader;
import waffle.windows.auth.IWindowsIdentity;
import waffle.windows.auth.PrincipalFormat;

/**
 * A Spring Negotiate security filter.
 * 
 * @author dblock[at]dblock[dot]org
 */
public class NegotiateSecurityFilter extends GenericFilterBean {

    /** The Constant LOGGER. */
    private static final Logger              LOGGER                  = LoggerFactory
                                                                             .getLogger(NegotiateSecurityFilter.class);
    
    /** The provider. */
    private SecurityFilterProviderCollection provider;
    
    /** The principal format. */
    private PrincipalFormat                  principalFormat         = PrincipalFormat.FQN;
    
    /** The role format. */
    private PrincipalFormat                  roleFormat              = PrincipalFormat.FQN;
    
    /** The allow guest login. */
    private boolean                          allowGuestLogin         = true;

    /** The granted authority factory. */
    private GrantedAuthorityFactory          grantedAuthorityFactory = WindowsAuthenticationToken.DEFAULT_GRANTED_AUTHORITY_FACTORY;
    
    /** The default granted authority. */
    private GrantedAuthority                 defaultGrantedAuthority = WindowsAuthenticationToken.DEFAULT_GRANTED_AUTHORITY;

    /**
     * Instantiates a new negotiate security filter.
     */
    public NegotiateSecurityFilter() {
        super();
        LOGGER.debug("[waffle.spring.NegotiateSecurityFilter] loaded");
    }

    /* (non-Javadoc)
     * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)
     */
    @Override
    public void doFilter(final ServletRequest req, final ServletResponse res, final FilterChain chain)
            throws IOException, ServletException {

        final HttpServletRequest request = (HttpServletRequest) req;
        final HttpServletResponse response = (HttpServletResponse) res;

        LOGGER.debug("{} {}, contentlength: {}", request.getMethod(), request.getRequestURI(),
                Integer.valueOf(request.getContentLength()));

        final AuthorizationHeader authorizationHeader = new AuthorizationHeader(request);

        // authenticate user
        if (!authorizationHeader.isNull()
                && this.provider.isSecurityPackageSupported(authorizationHeader.getSecurityPackage())) {

            // log the user in using the token
            IWindowsIdentity windowsIdentity;

            try {
                windowsIdentity = this.provider.doFilter(request, response);
                if (windowsIdentity == null) {
                    return;
                }
            } catch (IOException e) {
                LOGGER.warn("error logging in user: {}", e.getMessage());
                LOGGER.trace("{}", e);
                sendUnauthorized(response, true);
                return;
            }

            if (!this.allowGuestLogin && windowsIdentity.isGuest()) {
                LOGGER.warn("guest login disabled: {}", windowsIdentity.getFqn());
                sendUnauthorized(response, true);
                return;
            }

            try {
                LOGGER.debug("logged in user: {} ({})", windowsIdentity.getFqn(), windowsIdentity.getSidString());

                final WindowsPrincipal principal = new WindowsPrincipal(windowsIdentity, this.principalFormat,
                        this.roleFormat);

                LOGGER.debug("roles: {}", principal.getRolesString());

                final Authentication authentication = new WindowsAuthenticationToken(principal,
                        this.grantedAuthorityFactory, this.defaultGrantedAuthority);

                if (!setAuthentication(request, response, authentication)) {
                    return;
                }

                LOGGER.info("successfully logged in user: {}", windowsIdentity.getFqn());

            } finally {
                windowsIdentity.dispose();
            }
        }

        chain.doFilter(request, response);
    }

    /*
     * Invoked when authentication towards ad was succesful to populate securitycontext Override to add service provider
     * authorization checks.
     * 
     * @return if security context was set.
     */
    /**
     * Sets the authentication.
     *
     * @param request
     *            the request
     * @param response
     *            the response
     * @param authentication
     *            the authentication
     * @return true, if successful
     */
    protected boolean setAuthentication(final HttpServletRequest request, final HttpServletResponse response,
            final Authentication authentication) {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return true;
    }

    /* (non-Javadoc)
     * @see org.springframework.web.filter.GenericFilterBean#afterPropertiesSet()
     */
    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();

        if (this.provider == null) {
            throw new ServletException("Missing NegotiateSecurityFilter.Provider");
        }
    }

    /**
     * Send a 401 Unauthorized along with protocol authentication headers.
     * 
     * @param response
     *            HTTP Response
     * @param close
     *            Close connection.
     */
    protected void sendUnauthorized(final HttpServletResponse response, final boolean close) {
        try {
            this.provider.sendUnauthorized(response);
            if (close) {
                response.setHeader("Connection", "close");
            } else {
                response.setHeader("Connection", "keep-alive");
            }
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            response.flushBuffer();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Gets the principal format.
     *
     * @return the principal format
     */
    public PrincipalFormat getPrincipalFormat() {
        return this.principalFormat;
    }

    /**
     * Sets the principal format enum.
     *
     * @param value
     *            the new principal format enum
     */
    public void setPrincipalFormatEnum(final PrincipalFormat value) {
        this.principalFormat = value;
    }

    /**
     * Sets the principal format.
     *
     * @param value
     *            the new principal format
     */
    public void setPrincipalFormat(final String value) {
        this.setPrincipalFormatEnum(PrincipalFormat.valueOf(value.toUpperCase(Locale.ENGLISH)));
    }

    /**
     * Gets the role format.
     *
     * @return the role format
     */
    public PrincipalFormat getRoleFormat() {
        return this.roleFormat;
    }

    /**
     * Sets the role format enum.
     *
     * @param value
     *            the new role format enum
     */
    public void setRoleFormatEnum(final PrincipalFormat value) {
        this.roleFormat = value;
    }

    /**
     * Sets the role format.
     *
     * @param value
     *            the new role format
     */
    public void setRoleFormat(final String value) {
        this.setRoleFormatEnum(PrincipalFormat.valueOf(value.toUpperCase(Locale.ENGLISH)));
    }

    /**
     * Checks if is allow guest login.
     *
     * @return true, if is allow guest login
     */
    public boolean isAllowGuestLogin() {
        return this.allowGuestLogin;
    }

    /**
     * Sets the allow guest login.
     *
     * @param value
     *            the new allow guest login
     */
    public void setAllowGuestLogin(final boolean value) {
        this.allowGuestLogin = value;
    }

    /**
     * Gets the provider.
     *
     * @return the provider
     */
    public SecurityFilterProviderCollection getProvider() {
        return this.provider;
    }

    /**
     * Sets the provider.
     *
     * @param value
     *            the new provider
     */
    public void setProvider(final SecurityFilterProviderCollection value) {
        this.provider = value;
    }

    /**
     * Gets the granted authority factory.
     *
     * @return the granted authority factory
     */
    public GrantedAuthorityFactory getGrantedAuthorityFactory() {
        return this.grantedAuthorityFactory;
    }

    /**
     * Sets the granted authority factory.
     *
     * @param value
     *            the new granted authority factory
     */
    public void setGrantedAuthorityFactory(final GrantedAuthorityFactory value) {
        this.grantedAuthorityFactory = value;
    }

    /**
     * Gets the default granted authority.
     *
     * @return the default granted authority
     */
    public GrantedAuthority getDefaultGrantedAuthority() {
        return this.defaultGrantedAuthority;
    }

    /**
     * Sets the default granted authority.
     *
     * @param value
     *            the new default granted authority
     */
    public void setDefaultGrantedAuthority(final GrantedAuthority value) {
        this.defaultGrantedAuthority = value;
    }
}