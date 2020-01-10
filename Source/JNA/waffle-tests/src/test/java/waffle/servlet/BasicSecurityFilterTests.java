/*
 * Waffle (https://github.com/Waffle/waffle)
 *
 * Copyright (c) 2010-2019 Application Security, Inc.
 *
 * All rights reserved. This program and the accompanying materials are made available under the terms of the Eclipse
 * Public License v1.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v10.html.
 *
 * Contributors: Application Security, Inc.
 */
package waffle.servlet;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.security.auth.Subject;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;

import org.junit.jupiter.api.*;

import waffle.mock.MockWindowsAuthProvider;
import waffle.mock.http.SimpleFilterChain;
import waffle.mock.http.SimpleHttpRequest;
import waffle.mock.http.SimpleHttpResponse;
import waffle.windows.auth.impl.WindowsAccountImpl;

/**
 * Waffle Tomcat Security Filter Tests.
 *
 * @author dblock[at]dblock[dot]org
 */
public class BasicSecurityFilterTests {

    /** The filter. */
    private NegotiateSecurityFilter filter;
    private SimpleHttpRequest request;
    private SimpleHttpResponse response;
    private FilterChain filterChain;

    /**
     * Set up.
     * 
     * @throws javax.servlet.ServletException
     */
    @BeforeEach
    public void setUp() throws javax.servlet.ServletException {

        this.filter = new NegotiateSecurityFilter();
        this.filter.setAuth(new MockWindowsAuthProvider());
        this.filter.init(null);
        this.request = new SimpleHttpRequest();
        this.request.setMethod("GET");

        final String userHeaderValue = WindowsAccountImpl.getCurrentUsername() + ":password";
        final String basicAuthHeader = "Basic "
                + Base64.getEncoder().encodeToString(userHeaderValue.getBytes(StandardCharsets.UTF_8));
        this.request.addHeader("Authorization", basicAuthHeader);

        this.response = new SimpleHttpResponse();
        this.filterChain = new SimpleFilterChain();
    }

    /**
     * Tear down.
     */
    @AfterEach
    public void tearDown() {
        this.filter.destroy();
    }

    /**
     * Test basic auth.
     *
     * @throws IOException
     *             Signals that an I/O exception has occurred.
     * @throws ServletException
     *             the servlet exception
     */
    @Test
    public void testBasicAuth() throws IOException, ServletException {

        this.filter.doFilter(request, response, filterChain);
        final Subject subject = (Subject) request.getSession(false).getAttribute("javax.security.auth.subject");
        Assertions.assertNotNull(subject);
        assertThat(subject.getPrincipals().size()).isGreaterThan(0);
    }

    @Test
    public void testFailedBasicAuth() throws IOException, ServletException {
        this.filter.doFilter(request, response, filterChain);
        Assertions.assertEquals(401, response.getStatus());
    }

}
