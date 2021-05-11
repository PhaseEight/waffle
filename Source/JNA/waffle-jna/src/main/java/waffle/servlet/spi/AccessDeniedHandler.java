/*
 * MIT License
 *
 * Copyright (c) 2010-2021 The Waffle Project Contributors: https://github.com/Waffle/waffle/graphs/contributors
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

public class AccessDeniedHandler {

    static final String CONNECTION = "Connection";

    private AccessDeniedHandler() {
    }

    /**
     * Decide what to do with
     * 
     * @param authorizationHeader
     *            the parsed and processed Authorization Header created by a SecurityRequestFilter
     * @param providers
     *            the Security Providers configured on the Filter
     * @param response
     *            this is used to send the details to the client
     * @param responseErrorCode
     *            the error code to be send on the Reponse.sendError
     * 
     * @throws IOException
     *             if the response is closed before writting has completed
     * 
     */
    public static void sendUnauthorized(AuthorizationHeader authorizationHeader,
            SecurityFilterProviderCollection providers, HttpServletResponse response, int responseErrorCode)
            throws IOException {
        if (authorizationHeader.isNull()) {
            providers.sendAuthorizationHeaders(response);
            response.setHeader(AccessDeniedHandler.CONNECTION, "keep-alive");
            response.sendError(responseErrorCode);
        }
        if (authorizationHeader.isLogonAttempt() && response.getHeader(AccessDeniedHandler.CONNECTION) == null) {
            response.setHeader(AccessDeniedHandler.CONNECTION, "close");
            response.sendError(responseErrorCode);
        }
        if ((authorizationHeader.isSPNegTokenArgMessage() || authorizationHeader.isSPNegTokenInitMessage())
                && response.getHeader(AccessDeniedHandler.CONNECTION) == null) {
            response.sendError(responseErrorCode);
        }
        response.flushBuffer();
    }

}
