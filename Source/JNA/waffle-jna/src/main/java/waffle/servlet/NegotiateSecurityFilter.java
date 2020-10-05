/*
 * MIT License
 *
 * Copyright (c) 2010-2020 The Waffle Project Contributors: https://github.com/Waffle/waffle/graphs/contributors
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
 * Basic Authentication failures result in 403 Forbidden HTTP Status
 * 
 * @see <a href=
 *      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication">https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication</a>
 *      <a href="https://tools.ietf.org/html/rfc7617">https://tools.ietf.org/html/rfc7617</a>
 *      <a href="https://tools.ietf.org/html/rfc7235">https://tools.ietf.org/html/rfc7235</a>
 *
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

    /** The principal format. */
    private PrincipalFormat principalFormat = PrincipalFormat.FQN;

    /** The role format. */
    private PrincipalFormat roleFormat = PrincipalFormat.FQN;

    /** The providers. */
    private SecurityFilterProviderCollection providers;

    /** The auth. */
    private IWindowsAuthProvider auth;

    /** The exclusion filter. */
    private String[] excludePatterns;

    /** The allow guest login flag. */
    private boolean allowGuestLogin = true;

    /** The impersonate flag. */
    private boolean impersonate;

    /** The exclusion for bearer authorization flag. */
    private boolean supportBearerAuthorization;

    /** The exclusions for cors pre flight flag. */
    private boolean supportCorsPreflight;

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
        if (!Platform.isWindows()) {
            NegotiateSecurityFilter.LOGGER.info("Running in a non windows environment, SSO skipped");
            chain.doFilter(request, response);
            return;
        }

        // If this filter is disabled resume filter chain
        if (!this.isEnabled()) {
            NegotiateSecurityFilter.LOGGER.info("filter disabled, resuming filter chain");
            chain.doFilter(request, response);
            return;
        }

        // If excluded URL, resume the filter chain
        if (request.getRequestURL() != null && this.excludePatterns != null) {
            final String url = request.getRequestURL().toString();
            for (final String pattern : this.excludePatterns) {
                if (url.matches(pattern)) {
                    NegotiateSecurityFilter.LOGGER.info("Pattern :{} excluded URL:{}", url, pattern);
                    chain.doFilter(sreq, sres);
                    return;
                }
            }
        }

        // If exclude cores pre-flight and is pre flight, resume the filter chain
        if (this.supportCorsPreflight() && CorsPreFlightCheck.isPreflight(request)) {
            NegotiateSecurityFilter.LOGGER.info("[waffle.servlet.NegotiateSecurityFilter] CORS preflight");
            chain.doFilter(sreq, sres);
            return;
        }

        final AuthorizationHeader authorizationHeader = new AuthorizationHeader(request);

        // If exclude bearer authorization and is bearer authorization, resume the filter chain
        if (this.supportBearerAuthorization() && authorizationHeader.isBearerAuthorizationHeader()) {
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
            this.accessDenied(authorizationHeader, providers, response);
            return;
        }

        // authenticate user
        if (!authorizationHeader.isNull()) {

            // log the user in using the token
            IWindowsIdentity windowsIdentity;
            try {
                windowsIdentity = this.providers.doFilter(request, response);
                // standard behaviour for NTLM and Negotiate if the Providers have set WWW-Authenticate
                if (windowsIdentity == null) {
                    this.accessDenied(authorizationHeader, providers, response);
                    return;
                }
            } catch (final IOException e) {
                NegotiateSecurityFilter.AUTHENTICATION_LOGGER.warn("error logging in user using Auth Scheme [{}]: {}",
                        authorizationHeader.getSecurityPackage(), e.getMessage());
                this.accessDenied(authorizationHeader, providers, response);
                NegotiateSecurityFilter.LOGGER.trace("", e);
                return;
            }

            IWindowsImpersonationContext ctx = null;
            try {
                if (!this.allowGuestLogin && windowsIdentity.isGuest()) {
                    NegotiateSecurityFilter.AUTHENTICATION_LOGGER.warn("guest login disabled: {}",
                            windowsIdentity.getFqn());
                    this.accessDenied(authorizationHeader, providers, response);
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
                if (this.impersonate) {
                    windowsPrincipal = new AutoDisposableWindowsPrincipal(windowsIdentity, this.principalFormat,
                            this.roleFormat);
                } else {
                    windowsPrincipal = new WindowsPrincipal(windowsIdentity, this.principalFormat, this.roleFormat);
                }

                NegotiateSecurityFilter.LOGGER.info("roles: {}", windowsPrincipal.getRolesString());
                subject.getPrincipals().add(windowsPrincipal);
                request.getSession(false).setAttribute("javax.security.auth.subject", subject);

                NegotiateSecurityFilter.AUTHENTICATION_LOGGER.info("successfully logged in user: {}",
                        windowsIdentity.getFqn());

                request.getSession(false).setAttribute(NegotiateSecurityFilter.PRINCIPALSESSIONKEY, windowsPrincipal);

                final NegotiateRequestWrapper requestWrapper = new NegotiateRequestWrapper(request, windowsPrincipal);

                if (this.impersonate) {
                    NegotiateSecurityFilter.LOGGER.info("impersonating user");
                    ctx = windowsIdentity.impersonate();
                }

                chain.doFilter(requestWrapper, response);
            } finally {
                if (this.impersonate && ctx != null) {
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
     * @return True if a user already authenticated.
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

        if (this.providers.isPrincipalException(request)) {
            // the providers signal to authenticate despite an existing principal, eg. NTLM post
            return false;
        }

        // user already authenticated
        if (principal instanceof WindowsPrincipal) {
            NegotiateSecurityFilter.LOGGER.debug("previously authenticated Windows user: {}", principal.getName());
            final WindowsPrincipal windowsPrincipal = (WindowsPrincipal) principal;

            if (this.impersonate && windowsPrincipal.getIdentity() == null) {
                // This can happen when the session has been serialized then de-serialized
                // and because the IWindowsIdentity field is transient. In this case re-ask an
                // authentication to get a new identity.
                return false;
            }

            final NegotiateRequestWrapper requestWrapper = new NegotiateRequestWrapper(request, windowsPrincipal);

            IWindowsImpersonationContext ctx = null;
            if (this.impersonate) {
                NegotiateSecurityFilter.LOGGER.debug("re-impersonating user");
                ctx = windowsPrincipal.getIdentity().impersonate();
            }
            try {
                chain.doFilter(requestWrapper, response);
            } finally {
                if (this.impersonate && ctx != null) {
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

        String authProvider = null;
        String[] providerNames = null;
        if (filterConfig != null) {
            final List<String> parameterNames = Collections.list(filterConfig.getInitParameterNames());
            NegotiateSecurityFilter.LOGGER.debug("[waffle.servlet.NegotiateSecurityFilter] processing filterConfig");

            for (String parameterName : parameterNames) {
                final String parameterValue = filterConfig.getInitParameter(parameterName);
                NegotiateSecurityFilter.LOGGER.debug("Init Param: '{}={}'", parameterName, parameterValue);
                InitParameter initParam = InitParameter.get(parameterName);
                switch (initParam) {
                    case ACCESS_DENIED_STRATEGY:
                        this.setAccessDeniedStrategy(parameterValue);
                        break;
                    case DISABLE_SSO:
                        this.setEnabled(!Boolean.parseBoolean(parameterValue));
                        break;
                    case ENABLED:
                        this.setEnabled(Boolean.parseBoolean(parameterValue));
                        break;
                    case PRINCIPAL_FORMAT:
                        this.principalFormat = PrincipalFormat.valueOf(parameterValue.toUpperCase(Locale.ENGLISH));
                        break;
                    case ROLE_FORMAT:
                        this.roleFormat = PrincipalFormat.valueOf(parameterValue.toUpperCase(Locale.ENGLISH));
                        break;
                    case ALLOW_GUEST_LOGIN:
                        this.allowGuestLogin = Boolean.parseBoolean(parameterValue);
                        break;
                    case IMPERSONATE:
                        this.impersonate = Boolean.parseBoolean(parameterValue);
                        break;
                    case SECURITY_FILTER_PROVIDER:
                        providerNames = parameterValue.split("\\s+", -1);
                        break;
                    case AUTH_PROVIDER:
                        authProvider = parameterValue;
                        break;
                    case EXCLUDE_PATTERNS:
                        this.excludePatterns = parameterValue.split("\\s+", -1);
                        break;
                    case EXCLUDE_CORS_PREFLIGHT:
                    case SUPPORT_CORS_PREFLIGHT:
                        this.setSupportCorsPreflight(Boolean.parseBoolean(parameterValue));
                        break;
                    case SUPPORT_BEARER_AUTHORIZATION:
                    case EXCLUDE_BEARER_AUTHORIZATION:
                        this.setSupportBearerAuthorization(Boolean.parseBoolean(parameterValue));
                        break;
                    case PROVIDER_PARAMETER:
                        implParameters.put(parameterName, parameterValue);
                        break;
                    case UNSUPPORTED:
                        throw new ServletException(String.format("Invalid parameter: %s", parameterName));
                }
            }
        }

        NegotiateSecurityFilter.LOGGER.debug("[waffle.servlet.NegotiateSecurityFilter] authProvider");
        if (authProvider != null) {
            try {
                this.auth = (IWindowsAuthProvider) Class.forName(authProvider).getConstructor().newInstance();
            } catch (final ClassNotFoundException | IllegalArgumentException | SecurityException
                    | InstantiationException | IllegalAccessException | InvocationTargetException
                    | NoSuchMethodException e) {
                NegotiateSecurityFilter.LOGGER.error("error loading '{}': {}", authProvider, e.getMessage());
                NegotiateSecurityFilter.LOGGER.trace("", e);
                throw new ServletException(e);
            }
        }

        if (this.auth == null) {
            this.auth = new WindowsAuthProviderImpl();
        }

        if (providerNames != null) {
            this.providers = new SecurityFilterProviderCollection(providerNames, this.auth);
        }

        // create default providers if none specified
        if (this.providers == null) {
            NegotiateSecurityFilter.LOGGER.debug("initializing default security filter providers");
            this.providers = new SecurityFilterProviderCollection(this.auth);
        }

        // apply provider implementation parameters
        NegotiateSecurityFilter.LOGGER.debug("[waffle.servlet.NegotiateSecurityFilter] load provider parameters");
        for (final Map.Entry<String, String> implParameter : implParameters.entrySet()) {
            final String[] classAndParameter = implParameter.getKey().split("/", 2);
            if (classAndParameter.length == 2) {
                try {

                    NegotiateSecurityFilter.LOGGER.debug("setting {}, {}={}", classAndParameter[0],
                            classAndParameter[1], implParameter.getValue());

                    final SecurityFilterProvider provider = this.providers.getByClassName(classAndParameter[0]);
                    provider.initParameter(classAndParameter[1], implParameter.getValue());

                } catch (final ClassNotFoundException e) {
                    NegotiateSecurityFilter.LOGGER.error("invalid class: {} in {}", classAndParameter[0],
                            implParameter.getKey());
                    throw new ServletException(e);
                } catch (final Exception e) {
                    NegotiateSecurityFilter.LOGGER.error("{}: error setting '{}': {}", classAndParameter[0],
                            classAndParameter[1], e.getMessage());
                    NegotiateSecurityFilter.LOGGER.trace("", e);
                    throw new ServletException(e);
                }
            } else {
                NegotiateSecurityFilter.LOGGER.error("Invalid parameter: {}", implParameter.getKey());
                throw new ServletException("Invalid parameter: " + implParameter.getKey());
            }
        }

        NegotiateSecurityFilter.LOGGER.debug("[waffle.servlet.NegotiateSecurityFilter] started");
    }

    /**
     * Set the principal format.
     *
     * @param format
     *            Principal format.
     */
    public void setPrincipalFormat(final String format) {
        this.principalFormat = PrincipalFormat.valueOf(format.toUpperCase(Locale.ENGLISH));
        NegotiateSecurityFilter.LOGGER.debug("principal format: {}", this.principalFormat);
    }

    /**
     * Principal format.
     *
     * @return Principal format.
     */
    public PrincipalFormat getPrincipalFormat() {
        return this.principalFormat;
    }

    /**
     * Set the principal format.
     *
     * @param format
     *            Role format.
     */
    public void setRoleFormat(final String format) {
        this.roleFormat = PrincipalFormat.valueOf(format.toUpperCase(Locale.ENGLISH));
    }

    /**
     * Principal format.
     *
     * @return Role format.
     */
    public PrincipalFormat getRoleFormat() {
        return this.roleFormat;
    }

    /**
     * When a login attempt has failed, the accessDeniedHandler is called
     * 
     * @param response
     *            HTTP Response
     */
    private void accessDenied(final AuthorizationHeader authorizationHeader,
            final SecurityFilterProviderCollection providers, final HttpServletResponse response) {
        try {
            accessDeniedStrategy.handle(authorizationHeader, providers, response);
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
     * @return True if guest login is allowed, false otherwise.
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
     * @return true if impersonation is enabled, false otherwise
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
     * Checks if must continue if Authorization Authentication Scheme is Bearer
     *
     * @return true if Bearer Authorization is ignored, false otherwise
     */
    public boolean supportBearerAuthorization() {
        return this.supportBearerAuthorization;
    }

    public void setSupportBearerAuthorization(boolean supportBearerAuthorization) {
        this.supportBearerAuthorization = supportBearerAuthorization;
    }

    /**
     * Checks if must continue if Authorization Authentication Scheme is Bearer
     *
     * @return true if Bearer Authorization is ignored, false otherwise
     */
    public boolean supportCorsPreflight() {
        return this.supportCorsPreflight;
    }

    public void setSupportCorsPreflight(boolean supportCorsPreflight) {
        this.supportCorsPreflight = supportCorsPreflight;
    }

    /**
     * Returns the Access Denied Strategy Object
     *
     * @return accessDeniedHandler
     */
    public AccessDeniedStrategy getAccessDeniedStrategy() {
        return this.accessDeniedStrategy;
    }

    public void setAccessDeniedStrategy(String accessDeniedStrategy) throws ServletException {

        if ("HttpServletRequest.SC_UNAUTHORIZED".equalsIgnoreCase(accessDeniedStrategy)) {
            this.accessDeniedStrategy = new UnauthorizedAccessDeniedStrategy();
        } else if ("HttpServletRequest.SC_FORBIDDEN".equalsIgnoreCase(accessDeniedStrategy)) {
            this.accessDeniedStrategy = new ForbiddenAccessDeniedStrategy();
        } else {
            throw new ServletException(String.format("Unsupported Access Denied Strategy: %s; Supported values are HttpServletRequest.SC_UNAUTHORIZED and HttpServletRequest.SC_FORBIDDEN", accessDeniedStrategy));
        }

    }

    /** The enable filter flag. This will not not do any Windows Authentication */
    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public enum InitParameter {
        ACCESS_DENIED_STRATEGY("accessDeniedStrategy"),
        ENABLED("enabled"),
        DISABLE_SSO("disableSSO"),
        PRINCIPAL_FORMAT("principalFormat"),
        ROLE_FORMAT("roleFormat"),
        ALLOW_GUEST_LOGIN("allowGuestLogin"),
        IMPERSONATE("impersonate"),
        SECURITY_FILTER_PROVIDER("securityFilterProviders"),
        AUTH_PROVIDER("authProvider"),
        EXCLUDE_PATTERNS("excludePatterns"),
        EXCLUDE_CORS_PREFLIGHT("excludeCorsPreflight"),
        SUPPORT_CORS_PREFLIGHT("supportCorsPreflight"),
        SUPPORT_BEARER_AUTHORIZATION("excludeBearerAuthorization"),
        EXCLUDE_BEARER_AUTHORIZATION("supportBearerAuthorization"),
        PROVIDER_PARAMETER("provider"),
        UNSUPPORTED("unsupported");

        private final String paramName;

        public String getParamName() {
            return this.paramName;
        }

        public String toString() {
            return this.getParamName();
        }

        InitParameter(String name) {
            this.paramName = name;
        }

        private static final Map<String, InitParameter> lookup = new HashMap();
        static {
            // Create reverse lookup hash map
            for (InitParameter ip : InitParameter.values())
                lookup.put(ip.getParamName(), ip);
        }

        /*
         * checks if the paramter is valid or if the parameter is if style / identifying the parameter as a provider
         * provider parameter
         */
        public static InitParameter get(String paramName) {
            // the reverse lookup by simply getting
            // the value from the lookup HashMap.
            InitParameter parameter = lookup.get(paramName);
            if (parameter == null && paramName.indexOf("/") > 0) {
                parameter = PROVIDER_PARAMETER;
            }
            if (parameter == null) {
                parameter = UNSUPPORTED;
            }
            return parameter;
        }
    }
}
