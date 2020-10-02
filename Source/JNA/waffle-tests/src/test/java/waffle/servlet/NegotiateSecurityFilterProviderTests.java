/**
 * Waffle (https://github.com/Waffle/waffle)
 *
 * Copyright (c) 2010-2020 Application Security, Inc.
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

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;

import mockit.Expectations;
import mockit.Mocked;
import mockit.Tested;
import mockit.Verifications;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import waffle.mock.http.SimpleHttpResponse;
import waffle.servlet.spi.BasicSecurityFilterProvider;

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
    private NegotiateSecurityFilter filter = null;

    /**
     * Test cors and bearer authorization I init.
     *
     * @param filterConfig
     *            the filter config
     * @throws Exception
     *             the exception
     */
    @Test
    void testNegotiateSecurityFilterProviderWithEmptyCharset(@Mocked final FilterConfig filterConfig) throws Exception {

        final SimpleHttpResponse response = new SimpleHttpResponse();

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

        this.filter.init(filterConfig);

        final Field charset = (this.filter.getProviders().getByClassName(BasicSecurityFilterProvider.class.getName()))
                .getClass().getDeclaredField("charset");
        charset.setAccessible(true);

        Assertions.assertNull(
                charset.get(this.filter.getProviders().getByClassName(BasicSecurityFilterProvider.class.getName())));

        BasicSecurityFilterProvider provider = (BasicSecurityFilterProvider) this.filter.getProviders()
                .getByClassName(BasicSecurityFilterProvider.class.getName());
        provider.sendUnauthorized(response);
        Assertions.assertEquals("Basic realm=\"BasicSecurityFilterProvider\"", response.getHeader("WWW-Authenticate"));

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
    void testNegotiateSecurityFilterProviderWitUTF8Charset(@Mocked final FilterConfig filterConfig) throws Exception {

        final SimpleHttpResponse response = new SimpleHttpResponse();

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

        this.filter.init(filterConfig);

        final Field charset = (this.filter.getProviders().getByClassName(BasicSecurityFilterProvider.class.getName()))
                .getClass().getDeclaredField("charset");
        charset.setAccessible(true);

        Assertions.assertEquals(StandardCharsets.UTF_8,
                charset.get(this.filter.getProviders().getByClassName(BasicSecurityFilterProvider.class.getName())));

        BasicSecurityFilterProvider provider = (BasicSecurityFilterProvider) this.filter.getProviders()
                .getByClassName(BasicSecurityFilterProvider.class.getName());
        provider.sendUnauthorized(response);
        Assertions.assertEquals("Basic realm=\"BasicSecurityFilterProvider\", charset=\"UTF-8\"",
                response.getHeader("WWW-Authenticate"));

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
    void testNegotiateSecurityFilterProviderWitUSASCIICharset(@Mocked final FilterConfig filterConfig)
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

        this.filter.init(filterConfig);

        final Field charset = (this.filter.getProviders().getByClassName(BasicSecurityFilterProvider.class.getName()))
                .getClass().getDeclaredField("charset");
        charset.setAccessible(true);

        Assertions.assertEquals(StandardCharsets.US_ASCII,
                charset.get(this.filter.getProviders().getByClassName(BasicSecurityFilterProvider.class.getName())));

        new Verifications() {
            {
                filterConfig.getInitParameterNames();
                this.times = 1;
                filterConfig.getInitParameter(this.withInstanceOf(String.class));
                this.minTimes = 2;
            }
        };

    }

    @Test
    void testNegotiateSecurityFilterProviderWithInvalidCharset(@Mocked final FilterConfig filterConfig)
            throws Exception {

        final SimpleHttpResponse response = new SimpleHttpResponse();

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
                this.result = "NO-SUCH-CHARSET";
            }
        };

        Throwable thrown = Assertions.assertThrows(ServletException.class, () -> {
            this.filter.init(filterConfig);
        });

        Assertions.assertEquals(
                "java.nio.charset.UnsupportedCharsetException: Unsupported value for charset. Use an empty string, or UTF-8 or US-ASCII",
                thrown.getMessage());

        new Verifications() {
            {
                filterConfig.getInitParameterNames();
                this.times = 1;
                filterConfig.getInitParameter("securityFilterProviders");
                this.minTimes = 1;
                filterConfig.getInitParameter("waffle.servlet.spi.BasicSecurityFilterProvider/charset");
                this.times = 1;
            }
        };

    }

    @Test
    void testNegotiateSecurityFilterProviderWithUnsupportedCharset(@Mocked final FilterConfig filterConfig)
            throws Exception {

        final SimpleHttpResponse response = new SimpleHttpResponse();

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
                this.result = StandardCharsets.UTF_16.name();
            }
        };

        Throwable thrown = Assertions.assertThrows(ServletException.class, () -> {
            this.filter.init(filterConfig);
        });

        Assertions.assertEquals(
                "java.nio.charset.UnsupportedCharsetException: Unsupported value for charset. Use an empty string, or UTF-8 or US-ASCII",
                thrown.getMessage());

        new Verifications() {
            {
                filterConfig.getInitParameterNames();
                this.times = 1;
                filterConfig.getInitParameter("securityFilterProviders");
                this.times = 1;
                filterConfig.getInitParameter("waffle.servlet.spi.BasicSecurityFilterProvider/charset");
                this.times = 1;
            }
        };

    }

}
