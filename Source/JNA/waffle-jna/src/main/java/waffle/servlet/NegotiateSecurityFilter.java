/*
 * MIT License
 *
 * Copyright (c) 2010-2021 The Waffle Project Contributors: https://github.com/Waffle/waffle/graphs/contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package waffle.servlet;

import com.sun.jna.Platform;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.UnsupportedCharsetException;
import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.security.auth.Subject;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import waffle.servlet.spi.AccessDeniedStrategy;
import waffle.servlet.spi.ForbiddenAccessDeniedStrategy;
import waffle.servlet.spi.SecurityFilterProvider;
import waffle.servlet.spi.SecurityFilterProviderCollection;
import waffle.servlet.spi.UnauthorizedAccessDeniedStrategy;
import waffle.util.AuthorizationHeader;
import waffle.util.CorsPreFlightCheck;
import waffle.windows.auth.IWindowsAuthProvider;
import waffle.windows.auth.IWindowsIdentity;
import waffle.windows.auth.IWindowsImpersonationContext;
import waffle.windows.auth.PrincipalFormat;
import waffle.windows.auth.impl.WindowsAuthProviderImpl;

/**
 * A Negotiate (NTLM/Kerberos) Security Filter.
 *
 * @author dblock[at]dblock[dot]org*
 */
public class NegotiateSecurityFilter implements Filter {

    /** The Constant LOGGER. */
    private static final Logger LOGGER = LoggerFactory.getLogger(NegotiateSecurityFilter.class);
    private static final Logger AUTHENTICATION_LOGGER = LoggerFactory
            .getLogger(NegotiateSecurityFilter.class.getCanonicalName() + ".authentication");

    /** The Constant PRINCIPALSESSIONKEY. */
    private static final String PRINCIPALSESSIONKEY = NegotiateSecurityFilter.class.getName() + ".PRINCIPAL";

    private PrincipalFormat principalFormat = PrincipalFormat.FQN;

    private PrincipalFormat roleFormat = PrincipalFormat.FQN;

    private SecurityFilterProviderCollection providers;

    private String authProvider = null;
    private String[] providerNames = null;

    private IWindowsAuthProvider auth;

    private String[] excludePatterns;

    private boolean allowGuestLogin = true;

    private boolean impersonate;

    private boolean excludeBearerAuthorization;

    private boolean excludeCorsPreflight;

    private boolean enabled = true;

    private AccessDeniedStrategy accessDeniedStrategy = new UnauthorizedAccessDeniedStrategy();

    /**
     * Instantiates a new negotiate security filter.
     */
    public NegotiateSecurityFilter() {
        NegotiateSecurityFilter.LOGGER.debug("[waffle.servlet.NegotiateSecurityFilter] loaded");
    }

    @Override
    public void destroy() {
        NegotiateSecurityFilter.LOGGER.info("[waffle.servlet.NegotiateSecurityFilter] stopped");
    }

    @Override
    public void doFilter(final ServletRequest sreq, final ServletResponse sres, final FilterChain chain)
            throws IOException, ServletException {

        final HttpServletRequest request = (HttpServletRequest) sreq;
        final HttpServletResponse response = (HttpServletResponse) sres;

        NegotiateSecurityFilter.LOGGER.info("{} {}, contentlength: {}", request.getMethod(), request.getRequestURI(),
                request.getContentLength());

        // If we are not in a windows environment, resume filter chain
        if (!Platform.isWindows() || !this.isEnabled()) {
            NegotiateSecurityFilter.LOGGER.info("Running in a non windows environment, SSO skipped");
            chain.doFilter(request, response);
            return;
        }

        // If excluded URL, resume the filter chain
        if (request.getRequestURL() != null && this.getExcludePatterns() != null) {
            final String url = request.getRequestURL().toString();
            for (final String pattern : this.getExcludePatterns()) {
                if (url.matches(pattern)) {
                    NegotiateSecurityFilter.LOGGER.info("Pattern :{} excluded URL:{}", url, pattern);
                    chain.doFilter(sreq, sres);
                    return;
                }
            }
        }

        // If exclude cores pre-flight and is pre flight, resume the filter chain
        if (this.excludeCorsPreflight() && CorsPreFlightCheck.isPreflight(request)) {
            NegotiateSecurityFilter.LOGGER.info("[waffle.servlet.NegotiateSecurityFilter] CORS preflight");
            chain.doFilter(sreq, sres);
            return;
        }

        final AuthorizationHeader authorizationHeader = new AuthorizationHeader(request);

        // If exclude bearer authorization and is bearer authorization, resume the filter chain
        if (this.excludeBearerAuthorization() && authorizationHeader.isBearerAuthorizationHeader()) {
            NegotiateSecurityFilter.LOGGER.info("[waffle.servlet.NegotiateSecurityFilter] Authorization: Bearer");
            chain.doFilter(sreq, sres);
            return;
        }

        if (this.doFilterPrincipal(request, response, chain)) {
            // previously authenticated user
            return;
        }

        if (authorizationHeader.isNull()) {
            NegotiateSecurityFilter.LOGGER.info("authorization required");
            AccessDeniedStrategy.sendUnauthorized(authorizationHeader, getProviders(), response,
                    HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        // authenticate user
        if (!authorizationHeader.isNull()) {

            // log the user in using the token
            IWindowsIdentity windowsIdentity;
            try {
                windowsIdentity = this.getProviders().doFilter(request, response);
                // standard behaviour for NTLM and Negotiate if the Providers have set WWW-Authenticate
                if (windowsIdentity == null) {
                    this.accessDenied(authorizationHeader, getProviders(), response);
                    return;
                }
            } catch (final IOException e) {
                NegotiateSecurityFilter.AUTHENTICATION_LOGGER.warn("error logging in user using Auth Scheme [{}]: {}",
                        authorizationHeader.getSecurityPackage(), e.getMessage());
                this.accessDenied(authorizationHeader, getProviders(), response);
                NegotiateSecurityFilter.LOGGER.trace("", e);
                return;
            }

            IWindowsImpersonationContext ctx = null;
            try {
                if (!this.isAllowGuestLogin() && windowsIdentity.isGuest()) {
                    NegotiateSecurityFilter.AUTHENTICATION_LOGGER.warn("guest login disabled: {}",
                            windowsIdentity.getFqn());
                    this.accessDenied(authorizationHeader, getProviders(), response);
                    return;
                }

                NegotiateSecurityFilter.AUTHENTICATION_LOGGER.info("logged in user: {} ({})", windowsIdentity.getFqn(),
                        windowsIdentity.getSidString());

                final HttpSession session = request.getSession(true);
                if (session == null) {
                    throw new ServletException("Expected HttpSession");
                }

                Subject subject = (Subject) session.getAttribute("javax.security.auth.subject");
                if (subject == null) {
                    subject = new Subject();
                }

                WindowsPrincipal windowsPrincipal;
                if (this.isImpersonate()) {
                    windowsPrincipal = new AutoDisposableWindowsPrincipal(windowsIdentity, this.getPrincipalFormat(),
                            this.getRoleFormat());
                } else {
                    windowsPrincipal = new WindowsPrincipal(windowsIdentity, this.getPrincipalFormat(),
                            this.getRoleFormat());
                }

                NegotiateSecurityFilter.LOGGER.info("roles: {}", windowsPrincipal.getRolesString());
                subject.getPrincipals().add(windowsPrincipal);
                request.getSession(false).setAttribute("javax.security.auth.subject", subject);

                NegotiateSecurityFilter.AUTHENTICATION_LOGGER.info("successfully logged in user: {}",
                        windowsIdentity.getFqn());

                request.getSession(false).setAttribute(NegotiateSecurityFilter.PRINCIPALSESSIONKEY, windowsPrincipal);

                final NegotiateRequestWrapper requestWrapper = new NegotiateRequestWrapper(request, windowsPrincipal);

                if (this.isImpersonate()) {
                    NegotiateSecurityFilter.LOGGER.info("impersonating user");
                    ctx = windowsIdentity.impersonate();
                }

                chain.doFilter(requestWrapper, response);
            } finally {
                if (this.isImpersonate() && ctx != null) {
                    NegotiateSecurityFilter.LOGGER.info("terminating impersonation");
                    ctx.revertToSelf();
                } else {
                    windowsIdentity.dispose();
                }
            }
        }
    }

    /**
     * Filter for a previously logged on user.
     *
     * @param request
     *            HTTP request.
     * @param response
     *            HTTP response.
     * @param chain
     *            Filter chain.
     * @return boolean True if a user already authenticated.
     * @throws IOException
     *             Signals that an I/O exception has occurred.
     * @throws ServletException
     *             the servlet exception
     */
    private boolean doFilterPrincipal(final HttpServletRequest request, final HttpServletResponse response,
            final FilterChain chain) throws IOException, ServletException {
        Principal principal = request.getUserPrincipal();
        if (principal == null) {
            final HttpSession session = request.getSession(false);
            if (session != null) {
                principal = (Principal) session.getAttribute(NegotiateSecurityFilter.PRINCIPALSESSIONKEY);
            }
        }

        if (principal == null) {
            // no principal in this request
            return false;
        }

        if (this.getProviders().isPrincipalException(request)) {
            // the providers signal to authenticate despite an existing principal, eg. NTLM post
            return false;
        }

        // user already authenticated
        if (principal instanceof WindowsPrincipal) {
            NegotiateSecurityFilter.LOGGER.debug("previously authenticated Windows user: {}", principal.getName());
            final WindowsPrincipal windowsPrincipal = (WindowsPrincipal) principal;

            if (this.isImpersonate() && windowsPrincipal.getIdentity() == null) {
                // This can happen when the session has been serialized then de-serialized
                // and because the IWindowsIdentity field is transient. In this case re-ask an
                // authentication to get a new identity.
                return false;
            }

            final NegotiateRequestWrapper requestWrapper = new NegotiateRequestWrapper(request, windowsPrincipal);

            IWindowsImpersonationContext ctx = null;
            if (this.isImpersonate()) {
                NegotiateSecurityFilter.LOGGER.debug("re-impersonating user");
                ctx = windowsPrincipal.getIdentity().impersonate();
            }
            try {
                chain.doFilter(requestWrapper, response);
            } finally {
                if (this.isImpersonate() && ctx != null) {
                    NegotiateSecurityFilter.LOGGER.debug("terminating impersonation");
                    ctx.revertToSelf();
                }
            }
        } else {
            NegotiateSecurityFilter.LOGGER.debug("previously authenticated user: {}", principal.getName());
            chain.doFilter(request, response);
        }
        return true;
    }

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        final Map<String, String> implParameters = new HashMap<>();

        NegotiateSecurityFilter.LOGGER.debug("[waffle.servlet.NegotiateSecurityFilter] starting");

        if (filterConfig != null) {
            NegotiateSecurityFilter.LOGGER.debug("[waffle.servlet.NegotiateSecurityFilter] processing filterConfig");
            final List<String> parameterNames = Collections.list(filterConfig.getInitParameterNames());

            NegotiateSecurityFilter.LOGGER
                    .debug("[waffle.servlet.NegotiateSecurityFilter] Validate the Filter Config Init Parameters");
            validateInitParameters(parameterNames, filterConfig);

            // Validate the Filter Config Init Parameters
            NegotiateSecurityFilter.LOGGER
                    .debug("[waffle.servlet.NegotiateSecurityFilter] Retrieve All Implementation Parameters");
            for (String parameterName : parameterNames) {
                final String parameterValue = filterConfig.getInitParameter(parameterName);
                NegotiateSecurityFilter.LOGGER.debug("Retrieve Implementation Parameter Param: '{}={}'", parameterName,
                        parameterValue);
                if (parameterName.contains("/")) {
                    implParameters.put(parameterName, parameterValue);
                }
            }

            this.setAccessDeniedStrategy(filterConfig
                    .getInitParameter(NegotiateSecurityFilterInitParameter.ACCESS_DENIED_STRATEGY.getParamName()));

            this.setEnabled(Boolean.parseBoolean(
                    filterConfig.getInitParameter(NegotiateSecurityFilterInitParameter.ENABLED.getParamName()))
                    || !Boolean.parseBoolean(filterConfig
                            .getInitParameter(NegotiateSecurityFilterInitParameter.DISABLE_SSO.getParamName())));
            this.setPrincipalFormat(filterConfig
                    .getInitParameter(NegotiateSecurityFilterInitParameter.PRINCIPAL_FORMAT.getParamName()));
            this.setRoleFormat(
                    filterConfig.getInitParameter(NegotiateSecurityFilterInitParameter.ROLE_FORMAT.getParamName()));
            this.setAllowGuestLogin(filterConfig
                    .getInitParameter(NegotiateSecurityFilterInitParameter.ALLOW_GUEST_LOGIN.getParamName()));
            this.setImpersonate(Boolean.parseBoolean(
                    filterConfig.getInitParameter(NegotiateSecurityFilterInitParameter.IMPERSONATE.getParamName())));
            this.setProviderNames(filterConfig
                    .getInitParameter(NegotiateSecurityFilterInitParameter.SECURITY_FILTER_PROVIDER.getParamName()));
            this.setAuthProvider(
                    filterConfig.getInitParameter(NegotiateSecurityFilterInitParameter.AUTH_PROVIDER.getParamName()));
            this.setExcludePatterns(filterConfig
                    .getInitParameter(NegotiateSecurityFilterInitParameter.EXCLUDE_PATTERNS.getParamName()));

            this.setExcludeCorsPreflight(Boolean.parseBoolean(filterConfig
                    .getInitParameter(NegotiateSecurityFilterInitParameter.EXCLUDE_CORS_PREFLIGHT.getParamName())));

            this.setExcludeBearerAuthorization(Boolean.parseBoolean(filterConfig.getInitParameter(
                    NegotiateSecurityFilterInitParameter.EXCLUDE_BEARER_AUTHORIZATION.getParamName())));
        }

        configureAuthProvider();

        configureProviders(implParameters);

        NegotiateSecurityFilter.LOGGER.debug("[waffle.servlet.NegotiateSecurityFilter] started");
    }

    private void configureAuthProvider() throws ServletException {
        NegotiateSecurityFilter.LOGGER.debug("[waffle.servlet.NegotiateSecurityFilter] authProvider");
        if (getAuthProvider() != null) {
            try {
                final IWindowsAuthProvider auth = (IWindowsAuthProvider) Class.forName(getAuthProvider())
                        .getConstructor().newInstance();
                this.setAuth(auth);
            } catch (final ClassNotFoundException | IllegalArgumentException | SecurityException
                    | InstantiationException | IllegalAccessException | InvocationTargetException
                    | NoSuchMethodException e) {
                NegotiateSecurityFilter.LOGGER.error("cause of error loading '{}': {}", getAuthProvider(),
                        e.getCause());
                NegotiateSecurityFilter.LOGGER.error("error loading '{}': {}", getAuthProvider(), e.getMessage());
                NegotiateSecurityFilter.LOGGER.trace("", e);
                throw new ServletException(e);
            }
        }

        if (this.getAuth() == null) {
            this.setAuth(new WindowsAuthProviderImpl());
        }
    }

    private void validateInitParameters(List<String> parameterNames, FilterConfig filterConfig)
            throws ServletException {
        // check for invalid parameters
        for (String parameterName : parameterNames) {
            final String parameterValue = filterConfig.getInitParameter(parameterName);
            NegotiateSecurityFilter.LOGGER.debug("Validate Implementation Parameters Param: '{}={}'", parameterName,
                    parameterValue);
            if (NegotiateSecurityFilterInitParameter
                    .get(parameterName) == NegotiateSecurityFilterInitParameter.UNSUPPORTED) {
                NegotiateSecurityFilter.LOGGER.error("error loading '{}': {}", "Parameter is not supported",
                        parameterName);
                throw new ServletException(String.format("%s: %s", "Invalid parameter", parameterName));
            }
            if (NegotiateSecurityFilterInitParameter
                    .get(parameterName) == NegotiateSecurityFilterInitParameter.PROVIDER_PARAMETER
                    && parameterName.split("/").length != 2) {
                NegotiateSecurityFilter.LOGGER.debug("Invalid Implementation Parameter: '{}={}'", parameterName,
                        parameterValue);
                throw new ServletException(String.format("%s: %s", "Invalid Impl Parameter", parameterName));
            }

        }
    }

    private void configureProviders(final Map<String, String> implParameters) throws ServletException {
        final String[] providerNames = this.getProviderNames();
        if (providerNames != null) {
            this.setProviders(new SecurityFilterProviderCollection(providerNames, this.getAuth()));
        }
        // create default providers if none specified
        if (this.getProviders() == null) {
            NegotiateSecurityFilter.LOGGER.debug("initializing default security filter providers");
            this.setProviders(new SecurityFilterProviderCollection(this.getAuth()));
        }

        // apply provider implementation parameters
        NegotiateSecurityFilter.LOGGER.debug("[waffle.servlet.NegotiateSecurityFilter] load provider parameters");
        for (final Map.Entry<String, String> implParameter : implParameters.entrySet()) {
            final String[] classAndParameter = implParameter.getKey().split("/", 2);
            try {

                NegotiateSecurityFilter.LOGGER.debug("setting {}, {}={}", classAndParameter[0], classAndParameter[1],
                        implParameter.getValue());

                final SecurityFilterProvider provider = this.getProviders().getByClassName(classAndParameter[0]);
                provider.initParameter(classAndParameter[1], implParameter.getValue());

            } catch (final ClassNotFoundException e) {
                NegotiateSecurityFilter.LOGGER.error("invalid class: {} in {}", classAndParameter[0],
                        implParameter.getKey());
                throw new ServletException(e);
            } catch (final UnsupportedCharsetException e) {
                NegotiateSecurityFilter.LOGGER.error("invalid charset: {} in {}", implParameter,
                        implParameter.getValue());
                throw new ServletException(e);
            } catch (final Exception e) {
                NegotiateSecurityFilter.LOGGER.error("{}: error setting '{}': {}", classAndParameter[0],
                        classAndParameter[1], e.getMessage());
                NegotiateSecurityFilter.LOGGER.trace("", e);
                throw new ServletException(e);
            }
        }
    }

    /**
     *
     * @param format
     *            Principal format.
     *
     */
    private void setPrincipalFormat(final String format) {
        if (format != null) {
            this.setPrincipalFormat(PrincipalFormat.valueOf(format.toUpperCase(Locale.ENGLISH)));
        }
        NegotiateSecurityFilter.LOGGER.debug("principal format: {}", this.getPrincipalFormat());
    }

    /**
     *
     * @return PrincipalFormat Principal format.
     *
     */
    public PrincipalFormat getPrincipalFormat() {
        return this.principalFormat;
    }

    /**
     *
     * @param format
     *            Role format.
     *
     */
    public void setRoleFormat(final String format) {
        if (format != null) {
            this.setRoleFormat(PrincipalFormat.valueOf(format.toUpperCase(Locale.ENGLISH)));
        }
    }

    /**
     *
     * @return PrincipalFormat Role format.
     *
     */
    public PrincipalFormat getRoleFormat() {
        return this.roleFormat;
    }

    /**
     * When a login attempt has failed, the accessDeniedHandler is called
     *
     * @param authorizationHeader
     *            the requests authorizationHeader
     * @param providers
     *            the providers active for the filter
     * @param response
     *            HTTP Response that providers will update with their Authentication header
     *
     */
    private void accessDenied(final AuthorizationHeader authorizationHeader,
            final SecurityFilterProviderCollection providers, final HttpServletResponse response) {
        try {
            getAccessDeniedStrategy().handle(authorizationHeader, providers, response);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Windows auth provider.
     *
     * @return IWindowsAuthProvider.
     */
    public IWindowsAuthProvider getAuth() {
        return this.auth;
    }

    /**
     * Set Windows auth provider.
     *
     * @param provider
     *            Class implements IWindowsAuthProvider.
     */
    public void setAuth(final IWindowsAuthProvider provider) {
        this.auth = provider;
    }

    /**
     * True if guest login is allowed.
     *
     * @return boolean True if guest login is allowed, false otherwise.
     */
    public boolean isAllowGuestLogin() {
        return this.allowGuestLogin;
    }

    /**
     * Enable/Disable impersonation.
     *
     * @param value
     *            true to enable impersonation, false otherwise
     */
    public void setImpersonate(final boolean value) {
        this.impersonate = value;
    }

    /**
     * Checks if is impersonate.
     *
     * @return boolean true if impersonation is enabled, false otherwise
     */
    public boolean isImpersonate() {
        return this.impersonate;
    }

    /**
     * Security filter providers.
     *
     * @return A collection of security filter providers.
     */
    public SecurityFilterProviderCollection getProviders() {
        return this.providers;
    }

    /**
     *
     * @param excludeBearerAuthorization
     *            set to True to prevent he Filter from processing a request that has Authentication: Bearer
     *
     */
    protected void setExcludeBearerAuthorization(boolean excludeBearerAuthorization) {
        this.excludeBearerAuthorization = excludeBearerAuthorization;
    }

    /**
     *
     * @param excludeCorsPreflight
     *            set to True to prevent he Filter from processing a request that are CORS Preflight checks
     * @see <a href="https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request">MDN - Preflight request</a>
     *
     */
    protected void setExcludeCorsPreflight(boolean excludeCorsPreflight) {
        this.excludeCorsPreflight = excludeCorsPreflight;
    }

    /**
     * @return accessDeniedHandler the Access Denied Strategy Object default is 401
     */
    public AccessDeniedStrategy getAccessDeniedStrategy() {
        return this.accessDeniedStrategy;
    }

    protected void setAccessDeniedStrategy(String accessDeniedStrategy) throws ServletException {
        if (accessDeniedStrategy == null
                || "HttpServletResponse.SC_UNAUTHORIZED".equalsIgnoreCase(accessDeniedStrategy)) {
            this.setAccessDeniedStrategy(new UnauthorizedAccessDeniedStrategy());
        } else if ("HttpServletResponse.SC_FORBIDDEN".equalsIgnoreCase(accessDeniedStrategy)) {
            this.setAccessDeniedStrategy(new ForbiddenAccessDeniedStrategy());
        } else {
            throw new ServletException(String.format(
                    "Unsupported Access Denied Strategy: %s; Supported values are HttpServletResponse.SC_UNAUTHORIZED and HttpServletResponse.SC_FORBIDDEN",
                    accessDeniedStrategy));
        }

    }

    protected void setAccessDeniedStrategy(AccessDeniedStrategy accessDeniedStrategy) {
        this.accessDeniedStrategy = accessDeniedStrategy;
    }

    /**
     *
     * @return The enable filter flag. When not enabled the filter will not do any Windows Authentication
     *
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     *
     * @param enabled
     *            Set whether the filter must do any Windows Authentication
     *
     */
    protected void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    protected void setPrincipalFormat(PrincipalFormat principalFormat) {
        this.principalFormat = principalFormat;
    }

    protected void setRoleFormat(PrincipalFormat roleFormat) {
        this.roleFormat = roleFormat;
    }

    protected void setProviders(SecurityFilterProviderCollection providers) {
        this.providers = providers;
    }

    /**
     * @return String[] an array of path patterns that will be excluded from Windows Authentication
     */
    public String[] getExcludePatterns() {
        return excludePatterns;
    }

    /**
     * @param excludePatterns
     *            an array of paths that will be excluded from Windows Authentication
     */
    protected void setExcludePatterns(String excludePatterns) {
        if (excludePatterns != null) {
            this.excludePatterns = excludePatterns.split("\\s+", -1);
        }
    }

    /**
     *
     * @param allowGuestLogin
     *            Whether or not Windows Authentication should succeed for a windows Guest account
     *
     */
    protected void setAllowGuestLogin(String allowGuestLogin) {
        if (allowGuestLogin != null) {
            this.allowGuestLogin = Boolean.parseBoolean(allowGuestLogin);
        }
    }

    /**
     *
     * @return boolean True exclude Bearer Authentication Header from Windows Authentication Authentication: Bearer
     *         a_bearer_token
     *
     */
    public boolean excludeBearerAuthorization() {
        return excludeBearerAuthorization;
    }

    /**
     *
     * @return boolean True to prevent he Filter from processing a request that are CORS Preflight checks
     * @see <a href="https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request">MDN - Preflight request</a>
     *
     */
    public boolean excludeCorsPreflight() {
        return excludeCorsPreflight;
    }

    public String getAuthProvider() {
        return authProvider;
    }

    protected void setAuthProvider(String authProvider) {
        this.authProvider = authProvider;
    }

    public String[] getProviderNames() {
        return providerNames;
    }

    protected void setProviderNames(String providerNames) {
        if (providerNames != null) {
            this.providerNames = providerNames.split("\\s+", -1);
        }
    }
}
