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

public class ForbiddenAccessDeniedStrategy implements AccessDeniedStrategy {
    @Override
    public void handle(final AuthorizationHeader authorizationHeader, final SecurityFilterProviderCollection providers,
            final HttpServletResponse response) throws IOException {

        if (!(authorizationHeader.isNtlmType1PostAuthorizationHeader() || authorizationHeader.isNtlmType1Message())) {
            providers.sendUnauthorized(response);
        }

        if (authorizationHeader.isLogonAttempt()) {
            response.setHeader("Connection", "close");
        } else {
            response.setHeader("Connection", "keep-alive");
        }
        response.sendError(HttpServletResponse.SC_FORBIDDEN);
        response.flushBuffer();
    }
}
