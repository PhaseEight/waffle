/**
 * Waffle (https://github.com/Waffle/waffle)
 *
 * Copyright (c) 2010-2018 Application Security, Inc.
 *
 * All rights reserved. This program and the accompanying materials are made available under the terms of the Eclipse
 * Public License v1.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v10.html.
 *
 * Contributors: Application Security, Inc.
 */
package waffle.servlet;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Enumeration;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import mockit.Expectations;
import mockit.Mocked;
import mockit.Tested;
import mockit.Verifications;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import waffle.mock.http.SimpleFilterConfig;
import waffle.servlet.spi.BasicSecurityFilterProvider;
import waffle.util.CorsPreflightCheck;

/**
 * Waffle (https://github.com/Waffle/waffle)
 *
 * Copyright (c) 2010-2018 Application Security, Inc.
 *
 * All rights reserved. This program and the accompanying materials are made available under the terms of the Eclipse
 * Public License v1.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v10.html.
 *
 * Contributors: Application Security, Inc.
 */
class NegotiateSecurityFilterProviderTests {

    /** The negotiate security filter. */
    @Tested
    private NegotiateSecurityFilter negotiateSecurityFilter = null;

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

        /** The init parameter names. */
        final Enumeration<String> initParameterNames = Collections.enumeration(new java.util.ArrayList<String>() {

            /** The Constant serialVersionUID. */
            private static final long serialVersionUID = 1L;

            {
                this.add("principalFormat");
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

        this.negotiateSecurityFilter.init(filterConfig);

        final Field excludeCorsPreflight = this.negotiateSecurityFilter.getClass()
                .getDeclaredField("excludeCorsPreflight");
        excludeCorsPreflight.setAccessible(true);
        final Field excludeBearerAuthorization = this.negotiateSecurityFilter.getClass()
                .getDeclaredField("excludeBearerAuthorization");
        excludeBearerAuthorization.setAccessible(true);
        Assertions.assertTrue(excludeCorsPreflight.getBoolean(this.negotiateSecurityFilter));
        Assertions.assertTrue(excludeBearerAuthorization.getBoolean(this.negotiateSecurityFilter));
        Assertions.assertTrue(this.negotiateSecurityFilter.isImpersonate());
        Assertions.assertFalse(this.negotiateSecurityFilter.isAllowGuestLogin());

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

        /** The init parameter names. */
        final Enumeration<String> initParameterNames = Collections.enumeration(new java.util.ArrayList<String>() {

            /** The Constant serialVersionUID. */
            private static final long serialVersionUID = 1L;

            {
                this.add("principalFormat");
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
                filterConfig.getInitParameter(NegotiateSecurityFilter.InitParameter.PRINCIPAL_FORMAT.getParamName());
                this.result = "fqn";
                filterConfig.getInitParameter("roleFormat");
                this.result = "fqn";
                filterConfig.getInitParameter("allowGuestLogin");
                this.result = "false";
                filterConfig.getInitParameter("impersonate");
                this.result = "false";
                filterConfig.getInitParameter("securityFilterProviders");
                this.result = "waffle.servlet.spi.BasicSecurityFilterProvider\nwaffle.servlet.spi.NegotiateSecurityFilterProvider";
                filterConfig.getInitParameter("excludeCorsPreflight");
                this.result = "true";
                filterConfig.getInitParameter("excludeBearerAuthorization");
                this.result = "true";
                CorsPreflightCheck.isPreflight(request);
                this.result = true;
                request.getHeader("Authorization");
                this.result = "Bearer aBase64hash";
            }
        };

        this.negotiateSecurityFilter.init(filterConfig);
        this.negotiateSecurityFilter.doFilter(request, response, chain);

        new Verifications() {
            {
                chain.doFilter(request, response);
                this.times = 1;
            }
        };

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
    void testNegotiateSecurityFilterProviderWithNoCharset_init(@Mocked final FilterConfig filterConfig)
            throws Exception {

        Enumeration<String> initParameterNames = Collections.enumeration(new java.util.ArrayList<String>() {

            /** The Constant serialVersionUID. */
            private static final long serialVersionUID = 1L;

            {
                this.add("securityFilterProviders");
                this.add("waffle.servlet.spi.BasicSecurityFilterProvider/charset");
            }
        });

        new Expectations() {
            {
                filterConfig.getInitParameterNames();
                this.result = initParameterNames;
                filterConfig.getInitParameter("securityFilterProviders");
                this.result = "waffle.servlet.spi.BasicSecurityFilterProvider";
                filterConfig.getInitParameter("waffle.servlet.spi.BasicSecurityFilterProvider/charset");
                this.result = "";
            }
        };

        this.negotiateSecurityFilter.init(filterConfig);

        final Field charset = (this.negotiateSecurityFilter.getProviders()
                .getByClassName(BasicSecurityFilterProvider.class.getName())).getClass().getDeclaredField("charset");
        charset.setAccessible(true);

        final Field includeAuthenticationCharset = (this.negotiateSecurityFilter.getProviders()
                .getByClassName(BasicSecurityFilterProvider.class.getName())).getClass()
                        .getDeclaredField("includeAuthenticationCharset");
        includeAuthenticationCharset.setAccessible(true);

        Assertions.assertEquals(StandardCharsets.UTF_8, charset.get(this.negotiateSecurityFilter.getProviders()
                .getByClassName(BasicSecurityFilterProvider.class.getName())));

        Assertions.assertFalse(includeAuthenticationCharset.getBoolean(this.negotiateSecurityFilter.getProviders()
                .getByClassName(BasicSecurityFilterProvider.class.getName())));

        new Verifications() {
            {
                filterConfig.getInitParameter(this.withInstanceOf(String.class));
                this.minTimes = 2;
            }
        };

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
    void testNegotiateSecurityFilterProviderWitUTF8Charset_init(@Mocked final FilterConfig filterConfig)
            throws Exception {

        Enumeration<String> initParameterNames = Collections.enumeration(new java.util.ArrayList<String>() {

            /** The Constant serialVersionUID. */
            private static final long serialVersionUID = 1L;
            {
                this.add("securityFilterProviders");
                this.add("waffle.servlet.spi.BasicSecurityFilterProvider/charset");
            }
        });

        new Expectations() {
            {
                filterConfig.getInitParameterNames();
                this.result = initParameterNames;
                filterConfig.getInitParameter("securityFilterProviders");
                this.result = "waffle.servlet.spi.BasicSecurityFilterProvider";
                filterConfig.getInitParameter("waffle.servlet.spi.BasicSecurityFilterProvider/charset");
                this.result = "UTF-8";
            }
        };

        this.negotiateSecurityFilter.init(filterConfig);

        final Field charset = (this.negotiateSecurityFilter.getProviders()
                .getByClassName(BasicSecurityFilterProvider.class.getName())).getClass().getDeclaredField("charset");
        charset.setAccessible(true);

        final Field includeAuthenticationCharset = (this.negotiateSecurityFilter.getProviders()
                .getByClassName(BasicSecurityFilterProvider.class.getName())).getClass()
                        .getDeclaredField("includeAuthenticationCharset");
        includeAuthenticationCharset.setAccessible(true);

        Assertions.assertEquals(StandardCharsets.UTF_8, charset.get(this.negotiateSecurityFilter.getProviders()
                .getByClassName(BasicSecurityFilterProvider.class.getName())));

        Assertions.assertTrue(includeAuthenticationCharset.getBoolean(this.negotiateSecurityFilter.getProviders()
                .getByClassName(BasicSecurityFilterProvider.class.getName())));

        new Verifications() {
            {
                filterConfig.getInitParameter(this.withInstanceOf(String.class));
                this.minTimes = 2;
            }
        };

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
    void testNegotiateSecurityFilterProviderWitUSASCIICharset_init(@Mocked final FilterConfig filterConfig)
            throws Exception {

        Enumeration<String> initParameterNames = Collections.enumeration(new java.util.ArrayList<String>() {

            /** The Constant serialVersionUID. */
            private static final long serialVersionUID = 1L;

            {
                this.add("securityFilterProviders");
                this.add("waffle.servlet.spi.BasicSecurityFilterProvider/charset");
            }
        });

        new Expectations() {
            {
                filterConfig.getInitParameterNames();
                this.result = initParameterNames;
                filterConfig.getInitParameter("securityFilterProviders");
                this.result = "waffle.servlet.spi.BasicSecurityFilterProvider";
                filterConfig.getInitParameter("waffle.servlet.spi.BasicSecurityFilterProvider/charset");
                this.result = "US-ASCII";
            }
        };

        this.negotiateSecurityFilter.init(filterConfig);

        final Field charset = (this.negotiateSecurityFilter.getProviders()
                .getByClassName(BasicSecurityFilterProvider.class.getName())).getClass().getDeclaredField("charset");
        charset.setAccessible(true);

        final Field includeAuthenticationCharset = (this.negotiateSecurityFilter.getProviders()
                .getByClassName(BasicSecurityFilterProvider.class.getName())).getClass()
                        .getDeclaredField("includeAuthenticationCharset");
        includeAuthenticationCharset.setAccessible(true);

        Assertions.assertEquals(StandardCharsets.US_ASCII, charset.get(this.negotiateSecurityFilter.getProviders()
                .getByClassName(BasicSecurityFilterProvider.class.getName())));

        Assertions.assertTrue(includeAuthenticationCharset.getBoolean(this.negotiateSecurityFilter.getProviders()
                .getByClassName(BasicSecurityFilterProvider.class.getName())));

        new Verifications() {
            {
                filterConfig.getInitParameter(this.withInstanceOf(String.class));
                this.minTimes = 2;
            }
        };

    }

}
