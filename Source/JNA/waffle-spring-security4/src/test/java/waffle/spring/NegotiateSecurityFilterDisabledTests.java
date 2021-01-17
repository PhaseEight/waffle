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