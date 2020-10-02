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
package waffle.servlet.spi;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import waffle.util.AuthorizationHeader;

public class ForbiddenAccessDeniedStrategy implements AccessDeniedStrategy {
    @Override
    public void handle(final AuthorizationHeader authorizationHeader, final SecurityFilterProviderCollection providers,
            final HttpServletResponse response) throws IOException {

        if (!(authorizationHeader.isNtlmType1PostAuthorizationHeader() || authorizationHeader.isNtlmType1Message()
                || authorizationHeader.isSPNegTokenInitMessage() || authorizationHeader.isSPNegTokenArgMessage())) {
            providers.sendUnauthorized(response);
        }

        if (authorizationHeader.isLogonAttempt()) {
            /* response.setHeader("Connection", "close"); */
            response.setHeader("Connection", "close");
        } else {
            response.setHeader("Connection", "keep-alive");
        }
        response.sendError(HttpServletResponse.SC_FORBIDDEN);
        response.flushBuffer();
    }
}
