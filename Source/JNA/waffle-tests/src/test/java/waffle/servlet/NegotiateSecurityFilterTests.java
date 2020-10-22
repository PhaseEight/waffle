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

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.Secur32.EXTENDED_NAME_FORMAT;
import com.sun.jna.platform.win32.Secur32Util;
import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.platform.win32.SspiUtil.ManagedSecBufferDesc;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;

import javax.security.auth.Subject;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import mockit.Expectations;
import mockit.Mocked;
import mockit.Verifications;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import waffle.mock.MockWindowsAuthProvider;
import waffle.mock.MockWindowsIdentity;
import waffle.mock.http.SimpleFilterChain;
import waffle.mock.http.SimpleFilterConfig;
import waffle.mock.http.SimpleHttpRequest;
import waffle.mock.http.SimpleHttpResponse;
import waffle.servlet.spi.ForbiddenAccessDeniedStrategy;
import waffle.servlet.spi.SecurityFilterProvider;
import waffle.servlet.spi.UnauthorizedAccessDeniedStrategy;
import waffle.util.CorsPreFlightCheck;
import waffle.windows.auth.IWindowsCredentialsHandle;
import waffle.windows.auth.PrincipalFormat;
import waffle.windows.auth.impl.WindowsAccountImpl;
import waffle.windows.auth.impl.WindowsAuthProviderImpl;
import waffle.windows.auth.impl.WindowsCredentialsHandleImpl;
import waffle.windows.auth.impl.WindowsSecurityContextImpl;

/**
 * Waffle Tomcat Security Filter Tests.
 *
 * @author dblock[at]dblock[dot]org
 */
public class NegotiateSecurityFilterTests {

    /** The Constant NEGOTIATE. */
    private static final String NEGOTIATE = "Negotiate";

    /** The Constant NTLM. */
    private static final String NTLM = "NTLM";

    /** The filter. */
    private NegotiateSecurityFilter filter;

    /**
     * Sets the up.
     *
     * @throws ServletException
     *             the servlet exception
     */
    @BeforeEach
    void setUp() throws ServletException {
        this.filter = new NegotiateSecurityFilter();
        this.filter.setAuth(new WindowsAuthProviderImpl());
        this.filter.init(null);
    }

    /**
     * Tear down.
     */
    @AfterEach
    void tearDown() {
        this.filter.destroy();
    }

    /**
     * Test challenge get.
     *
     * @throws IOException
     *             Signals that an I/O exception has occurred.
     * @throws ServletException
     *             the servlet exception
     */
    @Test
    void testChallengeGET() throws IOException, ServletException {
        final SimpleHttpRequest request = new SimpleHttpRequest();
        request.setMethod("GET");
        final SimpleHttpResponse response = new SimpleHttpResponse();
        this.filter.doFilter(request, response, null);
        final String[] wwwAuthenticates = response.getHeaderValues("WWW-Authenticate");
        Assertions.assertEquals(3, wwwAuthenticates.length);
        Assertions.assertEquals(NegotiateSecurityFilterTests.NEGOTIATE, wwwAuthenticates[0]);
        Assertions.assertEquals(NegotiateSecurityFilterTests.NTLM, wwwAuthenticates[1]);
        Assertions.assertTrue(wwwAuthenticates[2].startsWith("Basic realm=\""));
        Assertions.assertEquals(2, response.getHeaderNamesSize());
        Assertions.assertEquals("keep-alive", response.getHeader("Connection"));
        Assertions.assertEquals(401, response.getStatus());
    }

    /**
     * Test challenge post.
     *
     * @throws IOException
     *             Signals that an I/O exception has occurred.
     * @throws ServletException
     *             the servlet exception
     */
    @Test
    void testChallengePOST() throws IOException, ServletException {
        final String securityPackage = NegotiateSecurityFilterTests.NEGOTIATE;
        IWindowsCredentialsHandle clientCredentials = null;
        WindowsSecurityContextImpl clientContext = null;
        try {
            // client credentials handle
            clientCredentials = WindowsCredentialsHandleImpl.getCurrent(securityPackage);
            clientCredentials.initialize();
            // initial client security context
            clientContext = new WindowsSecurityContextImpl();
            clientContext.setPrincipalName(WindowsAccountImpl.getCurrentUsername());
            clientContext.setCredentialsHandle(clientCredentials);
            clientContext.setSecurityPackage(securityPackage);
            clientContext.initialize(null, null, WindowsAccountImpl.getCurrentUsername());
            final SimpleHttpRequest request = new SimpleHttpRequest();
            request.setMethod("POST");
            request.setContentLength(0);
            final String clientToken = Base64.getEncoder().encodeToString(clientContext.getToken());
            request.addHeader("Authorization", securityPackage + " " + clientToken);
            final SimpleHttpResponse response = new SimpleHttpResponse();
            this.filter.doFilter(request, response, null);
            Assertions.assertTrue(response.getHeader("WWW-Authenticate").startsWith(securityPackage + " "));
            Assertions.assertEquals("keep-alive", response.getHeader("Connection"));
            Assertions.assertEquals(2, response.getHeaderNamesSize());
            Assertions.assertEquals(401, response.getStatus());
        } finally {
            if (clientContext != null) {
                clientContext.dispose();
            }
            if (clientCredentials != null) {
                clientCredentials.dispose();
            }
        }
    }

    /**
     * Test negotiate.
     *
     * @throws IOException
     *             Signals that an I/O exception has occurred.
     * @throws ServletException
     *             the servlet exception
     */
    @Test
    void testNegotiate() throws IOException, ServletException {
        final String securityPackage = NegotiateSecurityFilterTests.NEGOTIATE;
        // client credentials handle
        IWindowsCredentialsHandle clientCredentials = null;
        WindowsSecurityContextImpl clientContext = null;
        // role will contain both Everyone and SID
        this.filter.setRoleFormat("both");
        try {
            // client credentials handle
            clientCredentials = WindowsCredentialsHandleImpl.getCurrent(securityPackage);
            clientCredentials.initialize();
            // initial client security context
            clientContext = new WindowsSecurityContextImpl();
            clientContext.setPrincipalName(WindowsAccountImpl.getCurrentUsername());
            clientContext.setCredentialsHandle(clientCredentials);
            clientContext.setSecurityPackage(securityPackage);
            clientContext.initialize(null, null, WindowsAccountImpl.getCurrentUsername());
            // filter chain
            final SimpleFilterChain filterChain = new SimpleFilterChain();
            // negotiate
            boolean authenticated;
            final SimpleHttpRequest request = new SimpleHttpRequest();
            while (true) {
                final String clientToken = Base64.getEncoder().encodeToString(clientContext.getToken());
                request.addHeader("Authorization", securityPackage + " " + clientToken);

                final SimpleHttpResponse response = new SimpleHttpResponse();
                this.filter.doFilter(request, response, filterChain);

                final Subject subject = (Subject) request.getSession(false).getAttribute("javax.security.auth.subject");
                authenticated = (subject != null && subject.getPrincipals().size() > 0);

                if (authenticated) {
                    assertThat(response.getHeaderNamesSize()).isGreaterThanOrEqualTo(0);
                    break;
                }

                Assertions.assertTrue(response.getHeader("WWW-Authenticate").startsWith(securityPackage + " "));
                Assertions.assertEquals("keep-alive", response.getHeader("Connection"));
                Assertions.assertEquals(2, response.getHeaderNamesSize());
                Assertions.assertEquals(401, response.getStatus());
                final String continueToken = response.getHeader("WWW-Authenticate")
                        .substring(securityPackage.length() + 1);
                final byte[] continueTokenBytes = Base64.getDecoder().decode(continueToken);
                assertThat(continueTokenBytes.length).isPositive();
                final ManagedSecBufferDesc continueTokenBuffer = new ManagedSecBufferDesc(Sspi.SECBUFFER_TOKEN,
                        continueTokenBytes);
                clientContext.initialize(clientContext.getHandle(), continueTokenBuffer, "localhost");
            }
            Assertions.assertTrue(authenticated);
            Assertions.assertTrue(filterChain.getRequest() instanceof NegotiateRequestWrapper);
            Assertions.assertTrue(filterChain.getResponse() instanceof SimpleHttpResponse);
            final NegotiateRequestWrapper wrappedRequest = (NegotiateRequestWrapper) filterChain.getRequest();
            Assertions.assertEquals(NegotiateSecurityFilterTests.NEGOTIATE.toUpperCase(), wrappedRequest.getAuthType());
            Assertions.assertEquals(Secur32Util.getUserNameEx(EXTENDED_NAME_FORMAT.NameSamCompatible),
                    wrappedRequest.getRemoteUser());
            Assertions.assertTrue(wrappedRequest.getUserPrincipal() instanceof WindowsPrincipal);
            final String everyoneGroupName = Advapi32Util.getAccountBySid("S-1-1-0").name;
            Assertions.assertTrue(wrappedRequest.isUserInRole(everyoneGroupName));
            Assertions.assertTrue(wrappedRequest.isUserInRole("S-1-1-0"));
        } finally {
            if (clientContext != null) {
                clientContext.dispose();
            }
            if (clientCredentials != null) {
                clientCredentials.dispose();
            }
        }
    }

    /**
     * Test negotiate previous auth with windows principal.
     *
     * @throws IOException
     *             Signals that an I/O exception has occurred.
     * @throws ServletException
     *             the servlet exception
     */
    @Test
    void testNegotiatePreviousAuthWithWindowsPrincipal() throws IOException, ServletException {
        final MockWindowsIdentity mockWindowsIdentity = new MockWindowsIdentity("user", new ArrayList<>());
        final SimpleHttpRequest request = new SimpleHttpRequest();
        final WindowsPrincipal windowsPrincipal = new WindowsPrincipal(mockWindowsIdentity);
        request.setUserPrincipal(windowsPrincipal);
        final SimpleFilterChain filterChain = new SimpleFilterChain();
        final SimpleHttpResponse response = new SimpleHttpResponse();
        this.filter.doFilter(request, response, filterChain);
        Assertions.assertTrue(filterChain.getRequest() instanceof NegotiateRequestWrapper);
        final NegotiateRequestWrapper wrappedRequest = (NegotiateRequestWrapper) filterChain.getRequest();
        Assertions.assertTrue(wrappedRequest.getUserPrincipal() instanceof WindowsPrincipal);
        Assertions.assertEquals(windowsPrincipal, wrappedRequest.getUserPrincipal());
    }

    /**
     * Test challenge ntlmpost.
     *
     * @throws IOException
     *             Signals that an I/O exception has occurred.
     * @throws ServletException
     *             the servlet exception
     */
    @Test
    void testChallengeNTLMPOST() throws IOException, ServletException {
        final MockWindowsIdentity mockWindowsIdentity = new MockWindowsIdentity("user", new ArrayList<>());
        final SimpleHttpRequest request = new SimpleHttpRequest();
        final WindowsPrincipal windowsPrincipal = new WindowsPrincipal(mockWindowsIdentity);
        request.setUserPrincipal(windowsPrincipal);
        request.setMethod("POST");
        request.setContentLength(0);
        request.addHeader("Authorization", "NTLM TlRMTVNTUAABAAAABzIAAAYABgArAAAACwALACAAAABXT1JLU1RBVElPTkRPTUFJTg==");
        final SimpleFilterChain filterChain = new SimpleFilterChain();
        final SimpleHttpResponse response = new SimpleHttpResponse();
        this.filter.doFilter(request, response, filterChain);
        Assertions.assertEquals(401, response.getStatus());
        final String[] wwwAuthenticates = response.getHeaderValues("WWW-Authenticate");
        Assertions.assertEquals(1, wwwAuthenticates.length);
        Assertions.assertTrue(wwwAuthenticates[0].startsWith("NTLM "));
        Assertions.assertEquals(2, response.getHeaderNamesSize());
        Assertions.assertEquals("keep-alive", response.getHeader("Connection"));
        Assertions.assertEquals(401, response.getStatus());
    }

    /**
     * Test challenge ntlmput.
     *
     * @throws IOException
     *             Signals that an I/O exception has occurred.
     * @throws ServletException
     *             the servlet exception
     */
    @Test
    void testChallengeNTLMPUT() throws IOException, ServletException {
        final MockWindowsIdentity mockWindowsIdentity = new MockWindowsIdentity("user", new ArrayList<>());
        final SimpleHttpRequest request = new SimpleHttpRequest();
        final WindowsPrincipal windowsPrincipal = new WindowsPrincipal(mockWindowsIdentity);
        request.setUserPrincipal(windowsPrincipal);
        request.setMethod("PUT");
        request.setContentLength(0);
        request.addHeader("Authorization", "NTLM TlRMTVNTUAABAAAABzIAAAYABgArAAAACwALACAAAABXT1JLU1RBVElPTkRPTUFJTg==");
        final SimpleFilterChain filterChain = new SimpleFilterChain();
        final SimpleHttpResponse response = new SimpleHttpResponse();
        this.filter.doFilter(request, response, filterChain);
        Assertions.assertEquals(401, response.getStatus());
        final String[] wwwAuthenticates = response.getHeaderValues("WWW-Authenticate");
        Assertions.assertEquals(1, wwwAuthenticates.length);
        Assertions.assertTrue(wwwAuthenticates[0].startsWith("NTLM "));
        Assertions.assertEquals(2, response.getHeaderNamesSize());
        Assertions.assertEquals("keep-alive", response.getHeader("Connection"));
        Assertions.assertEquals(401, response.getStatus());
    }

    /**
     * Test challenge ntlmdelete.
     *
     * @throws IOException
     *             Signals that an I/O exception has occurred.
     * @throws ServletException
     *             the servlet exception
     */
    @Test
    void testChallengeNTLMDELETE() throws IOException, ServletException {
        final MockWindowsIdentity mockWindowsIdentity = new MockWindowsIdentity("user", new ArrayList<>());
        final SimpleHttpRequest request = new SimpleHttpRequest();
        final WindowsPrincipal windowsPrincipal = new WindowsPrincipal(mockWindowsIdentity);
        request.setUserPrincipal(windowsPrincipal);
        request.setMethod("DELETE");
        request.setContentLength(0);
        request.addHeader("Authorization", "NTLM TlRMTVNTUAABAAAABzIAAAYABgArAAAACwALACAAAABXT1JLU1RBVElPTkRPTUFJTg==");
        final SimpleFilterChain filterChain = new SimpleFilterChain();
        final SimpleHttpResponse response = new SimpleHttpResponse();
        this.filter.doFilter(request, response, filterChain);
        Assertions.assertEquals(401, response.getStatus());
        final String[] wwwAuthenticates = response.getHeaderValues("WWW-Authenticate");
        Assertions.assertEquals(1, wwwAuthenticates.length);
        Assertions.assertTrue(wwwAuthenticates[0].startsWith("NTLM "));
        Assertions.assertEquals(2, response.getHeaderNamesSize());
        Assertions.assertEquals("keep-alive", response.getHeader("Connection"));
        Assertions.assertEquals(401, response.getStatus());
    }

    @Test
    void testBasicSecurityFilterProviderForbidden() throws IOException, ServletException {
        final String userHeaderValue = "bad-user:password";
        final String basicAuthHeader = "Basic "
                + Base64.getEncoder().encodeToString(userHeaderValue.getBytes(StandardCharsets.UTF_8));
        final SimpleFilterChain filterChain = new SimpleFilterChain();
        final SimpleHttpRequest request = new SimpleHttpRequest();
        final SimpleHttpResponse response = new SimpleHttpResponse();
        final SimpleFilterConfig filterConfig = new SimpleFilterConfig();
        request.setMethod("POST");
        request.addHeader("Authorization", basicAuthHeader);
        filterConfig.setParameter("principalFormat", "sid");
        filterConfig.setParameter("roleFormat", "none");
        filterConfig.setParameter("allowGuestLogin", "true");
        filterConfig.setParameter("securityFilterProviders", "waffle.servlet.spi.BasicSecurityFilterProvider");
        filterConfig.setParameter("waffle.servlet.spi.BasicSecurityFilterProvider/realm", "DemoRealm");
        filterConfig.setParameter(NegotiateSecurityFilterInitParameter.ACCESS_DENIED_STRATEGY.getParamName(),
                "HttpServletRequest.SC_FORBIDDEN");
        this.filter.init(filterConfig);
        this.filter.doFilter(request, response, filterChain);
        final String[] wwwAuthenticates = response.getHeaderValues("WWW-Authenticate");
        Assertions.assertEquals(1, wwwAuthenticates.length);
        Assertions.assertTrue(wwwAuthenticates[0].startsWith("Basic "));
        Assertions.assertEquals("close", response.getHeader("Connection"));
        Assertions.assertEquals(2, response.getHeaderNamesSize());
        Assertions.assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
    }

    @Test
    void testBasicSecurityFilterProviderUnAuthorized() throws IOException, ServletException {
        final String userHeaderValue = "bad-user:password";
        final String basicAuthHeader = "Basic "
                + Base64.getEncoder().encodeToString(userHeaderValue.getBytes(StandardCharsets.UTF_8));
        final SimpleFilterChain filterChain = new SimpleFilterChain();
        final SimpleHttpRequest request = new SimpleHttpRequest();
        final SimpleHttpResponse response = new SimpleHttpResponse();
        final SimpleFilterConfig filterConfig = new SimpleFilterConfig();
        request.setMethod("POST");
        request.addHeader("Authorization", basicAuthHeader);
        filterConfig.setParameter("principalFormat", "sid");
        filterConfig.setParameter("roleFormat", "none");
        filterConfig.setParameter("allowGuestLogin", "true");
        filterConfig.setParameter("securityFilterProviders", "waffle.servlet.spi.BasicSecurityFilterProvider");
        filterConfig.setParameter("waffle.servlet.spi.BasicSecurityFilterProvider/realm", "DemoRealm");
        filterConfig.setParameter(NegotiateSecurityFilterInitParameter.ACCESS_DENIED_STRATEGY.getParamName(),
                "HttpServletRequest.SC_UNAUTHORIZED");
        this.filter.init(filterConfig);
        this.filter.doFilter(request, response, filterChain);
        final String[] wwwAuthenticates = response.getHeaderValues("WWW-Authenticate");
        Assertions.assertEquals(1, wwwAuthenticates.length);
        Assertions.assertTrue(wwwAuthenticates[0].startsWith("Basic "));
        Assertions.assertEquals("close", response.getHeader("Connection"));
        Assertions.assertEquals(2, response.getHeaderNamesSize());
        Assertions.assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
    }

    /**
     * Test init basic security filter provider.
     *
     * @throws ServletException
     *             the servlet exception
     */
    @Test
    void testInitBasicSecurityFilterProvider() throws ServletException {
        final SimpleFilterConfig filterConfig = new SimpleFilterConfig();
        filterConfig.setParameter("principalFormat", "sid");
        filterConfig.setParameter("roleFormat", "none");
        filterConfig.setParameter("allowGuestLogin", "true");
        filterConfig.setParameter("securityFilterProviders", "waffle.servlet.spi.BasicSecurityFilterProvider");
        filterConfig.setParameter("waffle.servlet.spi.BasicSecurityFilterProvider/realm", "DemoRealm");
        filterConfig.setParameter("authProvider", MockWindowsAuthProvider.class.getName());
        this.filter.init(filterConfig);
        Assertions.assertEquals(this.filter.getPrincipalFormat(), PrincipalFormat.SID);
        Assertions.assertEquals(this.filter.getRoleFormat(), PrincipalFormat.NONE);
        Assertions.assertTrue(this.filter.isAllowGuestLogin());
        Assertions.assertEquals(1, this.filter.getProviders().size());
        Assertions.assertTrue(this.filter.getAuth() instanceof MockWindowsAuthProvider);
    }

    /**
     * Test init basic security filter provider.
     *
     * @throws ServletException
     *             the servlet exception
     */
    @Test
    public void testInitBasicSecurityFilterProviderWithForbiddenAccessDeniedHandler() throws ServletException {
        final SimpleFilterConfig filterConfig = new SimpleFilterConfig();
        filterConfig.setParameter("principalFormat", "sid");
        filterConfig.setParameter("roleFormat", "none");
        filterConfig.setParameter("allowGuestLogin", "true");
        filterConfig.setParameter("securityFilterProviders", "waffle.servlet.spi.BasicSecurityFilterProvider");
        filterConfig.setParameter("waffle.servlet.spi.BasicSecurityFilterProvider/realm", "DemoRealm");
        filterConfig.setParameter("authProvider", MockWindowsAuthProvider.class.getName());
        filterConfig.setParameter(NegotiateSecurityFilterInitParameter.ACCESS_DENIED_STRATEGY.getParamName(),
                "HttpServletRequest.SC_FORBIDDEN");
        this.filter.init(filterConfig);
        Assertions.assertEquals(this.filter.getPrincipalFormat(), PrincipalFormat.SID);
        Assertions.assertEquals(this.filter.getRoleFormat(), PrincipalFormat.NONE);
        Assertions.assertTrue(this.filter.isAllowGuestLogin());
        Assertions.assertEquals(1, this.filter.getProviders().size());
        Assertions.assertTrue(this.filter.getAuth() instanceof MockWindowsAuthProvider);
        Assertions.assertTrue(this.filter.getAccessDeniedStrategy() instanceof ForbiddenAccessDeniedStrategy);
    }

    @Test
    public void testInitBasicSecurityFilterProviderWithUnauthorizedAccessDeniedHandler() throws ServletException {
        final SimpleFilterConfig filterConfig = new SimpleFilterConfig();
        filterConfig.setParameter("principalFormat", "sid");
        filterConfig.setParameter("roleFormat", "none");
        filterConfig.setParameter("allowGuestLogin", "true");
        filterConfig.setParameter("securityFilterProviders", "waffle.servlet.spi.BasicSecurityFilterProvider");
        filterConfig.setParameter("waffle.servlet.spi.BasicSecurityFilterProvider/realm", "DemoRealm");
        filterConfig.setParameter("authProvider", MockWindowsAuthProvider.class.getName());
        filterConfig.setParameter(NegotiateSecurityFilterInitParameter.ACCESS_DENIED_STRATEGY.getParamName(),
                "HttpServletRequest.SC_UNAUTHORIZED");
        this.filter.init(filterConfig);
        Assertions.assertEquals(this.filter.getPrincipalFormat(), PrincipalFormat.SID);
        Assertions.assertEquals(this.filter.getRoleFormat(), PrincipalFormat.NONE);
        Assertions.assertTrue(this.filter.isAllowGuestLogin());
        Assertions.assertEquals(1, this.filter.getProviders().size());
        Assertions.assertTrue(this.filter.getAuth() instanceof MockWindowsAuthProvider);
        Assertions.assertTrue(this.filter.getAccessDeniedStrategy() instanceof UnauthorizedAccessDeniedStrategy);
    }

    /**
     * Test init two security filter providers.
     *
     * @throws ServletException
     *             the servlet exception
     */
    @Test
    void testInitTwoSecurityFilterProviders() throws ServletException {
        // make sure that providers can be specified separated by any kind of space
        final SimpleFilterConfig filterConfig = new SimpleFilterConfig();
        filterConfig.setParameter("securityFilterProviders", "waffle.servlet.spi.BasicSecurityFilterProvider\n"
                + "waffle.servlet.spi.NegotiateSecurityFilterProvider waffle.servlet.spi.BasicSecurityFilterProvider");
        this.filter.init(filterConfig);
        Assertions.assertEquals(3, this.filter.getProviders().size());
    }

    /**
     * Test init two security filter providers.
     *
     * @throws ServletException
     *             the servlet exception
     */
    @Test
    public void testUseNegotiateSecurityFilterProviderFirst() throws ServletException, IOException {

        final SimpleHttpRequest request = new SimpleHttpRequest();
        request.setMethod("GET");
        final SimpleHttpResponse response = new SimpleHttpResponse();
        // make sure that providers can be specified separated by any kind of space
        final SimpleFilterConfig filterConfig = new SimpleFilterConfig();
        filterConfig.setParameter("securityFilterProviders",
                "waffle.servlet.spi.NegotiateSecurityFilterProvider waffle.servlet.spi.BasicSecurityFilterProvider");
        this.filter.init(filterConfig);
        final SimpleFilterChain filterChain = new SimpleFilterChain();
        this.filter.doFilter(request, response, filterChain);
        SecurityFilterProvider provider = this.filter.getProviders().get(0);
        Assertions.assertEquals(provider.getClass().getName(), "waffle.servlet.spi.NegotiateSecurityFilterProvider");
    }

    @Test
    public void testUseBasicSecurityFilterProviderFirst() throws ServletException, IOException {

        final SimpleHttpRequest request = new SimpleHttpRequest();
        request.setMethod("GET");
        final SimpleHttpResponse response = new SimpleHttpResponse();
        // make sure that providers can be specified separated by any kind of space
        final SimpleFilterConfig filterConfig = new SimpleFilterConfig();
        filterConfig.setParameter("securityFilterProviders",
                "waffle.servlet.spi.BasicSecurityFilterProvider waffle.servlet.spi.NegotiateSecurityFilterProvider");
        this.filter.init(filterConfig);
        final SimpleFilterChain filterChain = new SimpleFilterChain();
        this.filter.doFilter(request, response, filterChain);
        SecurityFilterProvider provider = this.filter.getProviders().get(0);
        Assertions.assertEquals(provider.getClass().getName(), "waffle.servlet.spi.BasicSecurityFilterProvider");
    }

    /**
     * Test init negotiate security filter provider.
     *
     * @throws ServletException
     *             the servlet exception
     */
    @Test
    void testInitNegotiateSecurityFilterProvider() throws ServletException {
        final SimpleFilterConfig filterConfig = new SimpleFilterConfig();
        filterConfig.setParameter("securityFilterProviders", "waffle.servlet.spi.NegotiateSecurityFilterProvider");
        filterConfig.setParameter("waffle.servlet.spi.NegotiateSecurityFilterProvider/protocols",
                "NTLM\nNegotiate NTLM");
        this.filter.init(filterConfig);
        Assertions.assertEquals(this.filter.getPrincipalFormat(), PrincipalFormat.FQN);
        Assertions.assertEquals(this.filter.getRoleFormat(), PrincipalFormat.FQN);
        Assertions.assertTrue(this.filter.isAllowGuestLogin());
        Assertions.assertEquals(1, this.filter.getProviders().size());
    }

    /**
     * Test init negotiate security filter provider invalid protocol.
     */
    @Test
    void testInitNegotiateSecurityFilterProviderInvalidProtocol() {
        final SimpleFilterConfig filterConfig = new SimpleFilterConfig();
        filterConfig.setParameter("securityFilterProviders", "waffle.servlet.spi.NegotiateSecurityFilterProvider");
        filterConfig.setParameter("waffle.servlet.spi.NegotiateSecurityFilterProvider/protocols", "INVALID");
        try {
            this.filter.init(filterConfig);
            Assertions.fail("expected ServletException");
        } catch (final ServletException e) {
            Assertions.assertEquals("java.lang.RuntimeException: Unsupported protocol: INVALID", e.getMessage());
        }
    }

    /**
     * Test init invalid parameter.
     */
    @Test
    void testInitInvalidParameter() {
        try {
            final SimpleFilterConfig filterConfig = new SimpleFilterConfig();
            filterConfig.setParameter("invalidParameter", "random");
            this.filter.init(filterConfig);
            Assertions.fail("expected ServletException");
        } catch (final ServletException e) {
            Assertions.assertEquals("Invalid parameter: invalidParameter", e.getMessage());
        }
    }

    /**
     * Test init invalid class in parameter.
     */
    @Test
    void testInitInvalidClassInParameter() {
        try {
            final SimpleFilterConfig filterConfig = new SimpleFilterConfig();
            filterConfig.setParameter("invalidClass/invalidParameter", "random");
            this.filter.init(filterConfig);
            Assertions.fail("expected ServletException");
        } catch (final ServletException e) {
            Assertions.assertEquals("java.lang.ClassNotFoundException: invalidClass", e.getMessage());
        }
    }

    /**
     * Test cors and bearer authorization I init.
     *
     * @param filterConfig
     *            the filter config
     * @throws Exception
     *             the exception
     */
    @Test
    void testCorsAndBearerAuthorizationI_init(@Mocked final FilterConfig filterConfig) throws Exception {

        /* The init parameter names. */
        final Enumeration<String> initParameterNames = Collections.enumeration(new java.util.ArrayList<String>() {

            /** The Constant serialVersionUID. */
            private static final long serialVersionUID = 1L;

            {
                this.add("principalFormat");
                this.add("roleFormat");
                this.add("allowGuestLogin");
                this.add("impersonate");
                this.add("securityFilterProviders");
                this.add("excludePatterns");
                this.add("excludeCorsPreflight");
                this.add("excludeBearerAuthorization");
            }
        });

        new Expectations() {
            {
                filterConfig.getInitParameterNames();
                this.result = initParameterNames;
                filterConfig.getInitParameter("principalFormat");
                this.result = "fqn";
                filterConfig.getInitParameter("roleFormat");
                this.result = "fqn";
                filterConfig.getInitParameter("allowGuestLogin");
                this.result = "false";
                filterConfig.getInitParameter("impersonate");
                this.result = "true";
                filterConfig.getInitParameter("securityFilterProviders");
                this.result = "waffle.servlet.spi.BasicSecurityFilterProvider\nwaffle.servlet.spi.NegotiateSecurityFilterProvider";
                filterConfig.getInitParameter("excludePatterns");
                this.result = ".*/peter/.*";
                filterConfig.getInitParameter("excludeCorsPreflight");
                this.result = "true";
                filterConfig.getInitParameter("excludeBearerAuthorization");
                this.result = "true";
            }
        };

        this.filter.init(filterConfig);

        final Field supportCorsPreflight = this.filter.getClass().getDeclaredField("supportCorsPreflight");
        supportCorsPreflight.setAccessible(true);
        final Field supportBearerAuthorization = this.filter.getClass().getDeclaredField("supportBearerAuthorization");
        supportBearerAuthorization.setAccessible(true);
        Assertions.assertTrue(supportCorsPreflight.getBoolean(this.filter));
        Assertions.assertTrue(supportBearerAuthorization.getBoolean(this.filter));
        Assertions.assertTrue(this.filter.isImpersonate());
        Assertions.assertFalse(this.filter.isAllowGuestLogin());

        new Verifications() {
            {
                filterConfig.getInitParameter(this.withInstanceOf(String.class));
                this.minTimes = 8;
            }
        };

    }

    /**
     * Test exclude cors and OAUTH bearer authorization do filter.
     *
     * @param request
     *            the request
     * @param response
     *            the response
     * @param chain
     *            the chain
     * @param filterConfig
     *            the filter config
     * @throws Exception
     *             the exception
     */
    @Test
    void testExcludeCorsAndOAUTHBearerAuthorization_doFilter(@Mocked final HttpServletRequest request,
            @Mocked final HttpServletResponse response, @Mocked final FilterChain chain,
            @Mocked final FilterConfig filterConfig) throws Exception {

        /* The init parameter names. */
        final Enumeration<String> initParameterNames = Collections.enumeration(new java.util.ArrayList<String>() {

            /** The Constant serialVersionUID. */
            private static final long serialVersionUID = 1L;

            {
                this.add("principalFormat");
                this.add("roleFormat");
                this.add("allowGuestLogin");
                this.add("impersonate");
                this.add("securityFilterProviders");
                this.add("excludeCorsPreflight");
                this.add("excludeBearerAuthorization");
            }
        });

        new Expectations() {
            {
                filterConfig.getInitParameterNames();
                this.result = initParameterNames;
                filterConfig.getInitParameter(NegotiateSecurityFilterInitParameter.PRINCIPAL_FORMAT.getParamName());
                this.result = "fqn";
                filterConfig.getInitParameter("roleFormat");
                this.result = "fqn";
                filterConfig.getInitParameter("allowGuestLogin");
                this.result = "false";
                filterConfig.getInitParameter("impersonate");
                this.result = "false";
                filterConfig.getInitParameter("securityFilterProviders");
                this.result = "waffle.servlet.spi.NegotiateSecurityFilterProvider\nwaffle.servlet.spi.BasicSecurityFilterProvider";
                filterConfig.getInitParameter("excludeCorsPreflight");
                this.result = "true";
                filterConfig.getInitParameter("excludeBearerAuthorization");
                this.result = "true";
                CorsPreFlightCheck.isPreflight(request);
                this.result = true;
                request.getHeader("Authorization");
                this.result = "Bearer aBase64hash";
            }
        };

        this.filter.init(filterConfig);
        this.filter.doFilter(request, response, chain);

        new Verifications() {
            {
                chain.doFilter(request, response);
                this.times = 1;
            }
        };

    }

    /**
     * Test exclude cors and OAUTH bearer authorization do filter.
     *
     * @param request
     *            the request
     * @param response
     *            the response
     * @param chain
     *            the chain
     * @param filterConfig
     *            the filter config
     * @throws Exception
     *             the exception
     */
    @Test
    void testNotEnabledFilter(@Mocked final HttpServletRequest request, @Mocked final HttpServletResponse response,
            @Mocked final FilterChain chain, @Mocked final FilterConfig filterConfig) throws Exception {

        /* The init parameter names. */
        final Enumeration<String> initParameterNames = Collections.enumeration(new java.util.ArrayList<String>() {

            /** The Constant serialVersionUID. */
            private static final long serialVersionUID = 1L;

            {
                this.add("enabled");
            }
        });

        new Expectations() {
            {
                filterConfig.getInitParameterNames();
                this.result = initParameterNames;
                filterConfig.getInitParameter(NegotiateSecurityFilterInitParameter.ENABLED.getParamName());
                this.result = "false";
            }
        };

        this.filter.init(filterConfig);
        this.filter.doFilter(request, response, chain);

        new Verifications() {
            {
                filterConfig.getInitParameterNames();
                this.times = 1;
                filterConfig.getInitParameter(this.withInstanceOf(String.class));
                this.minTimes = 1;
                chain.doFilter(request, response);
                this.times = 1;
            }
        };

    }

}
