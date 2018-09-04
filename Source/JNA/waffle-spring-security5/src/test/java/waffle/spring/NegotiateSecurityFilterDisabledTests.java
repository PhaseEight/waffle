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
package waffle.spring;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.AbstractApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.core.context.SecurityContextHolder;

import waffle.windows.auth.PrincipalFormat;

/**
 * The Class NegotiateSecurityFilterTests.
 *
 * @author dblock[at]dblock[dot]org
 */
public class NegotiateSecurityFilterDisabledTests {

    /** The filter. */
    private NegotiateSecurityFilter filter;

    /** The ctx. */
    private ApplicationContext ctx;

    /**
     * Sets the up.
     */
    @BeforeEach
    public void setUp() {
        final String[] configFiles = new String[] { "springTestFilterBeans.xml" };
        this.ctx = new ClassPathXmlApplicationContext(configFiles);
        SecurityContextHolder.getContext().setAuthentication(null);
        this.filter = (NegotiateSecurityFilter) this.ctx.getBean("waffleDisabledNegotiateSecurityFilter");
    }

    /**
     * Shut down.
     */
    @AfterEach
    public void shutDown() {
        ((AbstractApplicationContext) this.ctx).close();
    }

    /**
     * Test filter.
     */
    @Test
    public void testFilterIsDisabled() {
        Assertions.assertFalse(this.filter.isAllowGuestLogin());
        Assertions.assertEquals(PrincipalFormat.FQN, this.filter.getPrincipalFormat());
        Assertions.assertEquals(PrincipalFormat.BOTH, this.filter.getRoleFormat());
        Assertions.assertNull(this.filter.getFilterConfig());
        Assertions.assertNotNull(this.filter.getProvider());
        Assertions.assertFalse(this.filter.isEnabled());
    }

}
