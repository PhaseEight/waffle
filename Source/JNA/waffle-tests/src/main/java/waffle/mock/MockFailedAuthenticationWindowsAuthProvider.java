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
/*
  Waffle (https://github.com/Waffle/waffle)

  Copyright (c) 2010-2019 Application Security, Inc.

  All rights reserved. This program and the accompanying materials are made available under the terms of the Eclipse
  Public License v1.0 which accompanies this distribution, and is available at
  https://www.eclipse.org/legal/epl-v10.html.

  Contributors: Application Security, Inc.
 */
package waffle.mock;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import waffle.windows.auth.*;

/**
 * The Class MockWindowsAuthProvider.
 *
 * @author dblock[at]dblock[dot]org
 */
public class MockFailedAuthenticationWindowsAuthProvider implements IWindowsAuthProvider {

    /** The Constant GUEST. */
    private static final String GUEST = "Guest";

    /** The groups. */
    private final List<String> groups = new ArrayList<>();

    /**
     * Instantiates a new mock windows auth provider.
     */
    public MockFailedAuthenticationWindowsAuthProvider() {
        this.groups.add("Users");
        this.groups.add("Everyone");
    }

    /**
     * Adds the group.
     *
     * @param name
     *            the name
     */
    public void addGroup(final String name) {
        this.groups.add(name);
    }

    @Override
    public IWindowsSecurityContext acceptSecurityToken(final String connectionId, final byte[] token,
            final String securityPackage) {
        return new MockWindowsSecurityContext(new String(token, StandardCharsets.UTF_8));
    }

    @Override
    public IWindowsComputer getCurrentComputer() {
        return null;
    }

    @Override
    public IWindowsDomain[] getDomains() {
        return new IWindowsDomain[0];
    }

    @Override
    public IWindowsIdentity logonDomainUser(final String username, final String domain, final String password) {
        return null;
    }

    @Override
    public IWindowsIdentity logonDomainUserEx(final String username, final String domain, final String password,
            final int logonType, final int logonProvider) {
        return null;
    }

    /**
     * Will login the current user with any password. Will logon a "Guest" user as guest.
     *
     * @param username
     *            the username
     * @param password
     *            the password
     * @return the i windows identity
     */
    @Override
    public IWindowsIdentity logonUser(final String username, final String password) {
        return null;
    }

    @Override
    public IWindowsAccount lookupAccount(final String username) {
        return null;
    }

    @Override
    public void resetSecurityToken(final String connectionId) {
        // Do Nothing
    }

}
