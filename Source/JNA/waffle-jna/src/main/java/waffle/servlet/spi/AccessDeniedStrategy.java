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
package waffle.servlet.spi;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import waffle.util.AuthorizationHeader;

public interface AccessDeniedStrategy {

    /**
     * Decide what to do with
     * 
     * @param authorizationHeader
     *            the parsed and processed Authorization Header created by a SecurityRequestFilter
     * @param providers
     *            the Security Providers configured on the Filter
     * @param response
     *            this is used to send the details to the client
     * @throws IOException
     *             is thrown while trying to write on the response to the client
     */
    void handle(AuthorizationHeader authorizationHeader, SecurityFilterProviderCollection providers,
            HttpServletResponse response) throws IOException;
}
