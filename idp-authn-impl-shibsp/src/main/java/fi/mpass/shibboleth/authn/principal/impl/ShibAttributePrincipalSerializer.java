/*
 * The MIT License
 * Copyright (c) 2015 CSC - IT Center for Science, http://www.csc.fi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package fi.mpass.shibboleth.authn.principal.impl;

import java.security.Principal;
import java.util.regex.Pattern;

import javax.annotation.Nonnull;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

/**
 * Serializer for {@link ShibAttributePrincipal}.
 */
public class ShibAttributePrincipalSerializer extends KeyValuePrincipalSerializer<ShibAttributePrincipal> {
    
    /** Pattern used to determine if input is supported. */
    @Nonnull private static final Pattern JSON_PATTERN = 
            Pattern.compile("^\\{\"shibAttrKey\":.*,\"shibAttrValue\":.*\\}$");

    /** {@inheritDoc} */
    @Override
    public boolean supports(@Nonnull final Principal principal) {
        return principal instanceof ShibAttributePrincipal;
    }

    /** {@inheritDoc} */
    @Override
    public boolean supports(@Nonnull @NotEmpty final String value) {
        return JSON_PATTERN.matcher(value).matches();
    }


    /** {@inheritDoc} */
    @Override
    public @Nonnull @NotEmpty String getKeyField() {
        return "shibAttrKey";
    }

    /** {@inheritDoc} */
    @Override
    public @Nonnull @NotEmpty String getValueField() {
        return "shibAttrValue";
    }

    /** {@inheritDoc} */
    @Override
    public ShibAttributePrincipal construct(String key, String value) {
        return new ShibAttributePrincipal(key, value);
    }
}