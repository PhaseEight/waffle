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
package waffle.servlet;

import java.util.HashMap;
import java.util.Map;

public enum NegotiateSecurityFilterInitParameter {
    ACCESS_DENIED_STRATEGY("accessDeniedStrategy"),
    ENABLED("enabled"),
    DISABLE_SSO("disableSSO"),
    PRINCIPAL_FORMAT("principalFormat"),
    ROLE_FORMAT("roleFormat"),
    ALLOW_GUEST_LOGIN("allowGuestLogin"),
    IMPERSONATE("impersonate"),
    SECURITY_FILTER_PROVIDER("securityFilterProviders"),
    AUTH_PROVIDER("authProvider"),
    EXCLUDE_PATTERNS("excludePatterns"),
    EXCLUDE_CORS_PREFLIGHT("excludeCorsPreflight"),
    EXCLUDE_BEARER_AUTHORIZATION("excludeBearerAuthorization"),
    PROVIDER_PARAMETER("provider"),
    UNSUPPORTED("unsupported");

    private final String paramName;
    private static final Map<String, NegotiateSecurityFilterInitParameter> lookup = new HashMap<>();
    static {
        // Create reverse lookup hash map
        for (NegotiateSecurityFilterInitParameter ip : NegotiateSecurityFilterInitParameter.values())
            lookup.put(ip.getParamName(), ip);
    }

    public String getParamName() {
        return this.paramName;
    }

    @Override
    public String toString() {
        return this.getParamName();
    }

    NegotiateSecurityFilterInitParameter(String name) {
        this.paramName = name;
    }

    /*
     * check if the parameter is valid or if the parameter contains / identifying the parameter as a provider parameter
     */
    public static NegotiateSecurityFilterInitParameter get(String paramName) {
        // the reverse lookup by simply getting
        // the value from the lookup HashMap.
        NegotiateSecurityFilterInitParameter parameter = lookup.get(paramName);
        if (parameter == null && (paramName.contains("/"))) {
            parameter = PROVIDER_PARAMETER;
        }
        if (parameter == null) {
            parameter = UNSUPPORTED;
        }
        return parameter;
    }

}
