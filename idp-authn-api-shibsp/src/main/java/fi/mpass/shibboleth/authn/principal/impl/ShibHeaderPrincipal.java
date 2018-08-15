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

import javax.annotation.Nonnull;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

/**
 * This class is designed to carry HTTP header key and value -pairs inside {@link Principal}.
 */
public class ShibHeaderPrincipal extends KeyValuePrincipal {

    /**
     * Constructor.
     * 
     * @param theName containing the key and the value, separated by '<=>'
     */
    public ShibHeaderPrincipal(@Nonnull @NotEmpty final String theName) {
        super(theName);
    }

    /**
     * Constructor.
     * 
     * @param theKey the key, can not be null or empty
     * @param theValue the value corresponding to the key, can not be null or empty
     */
    public ShibHeaderPrincipal(@Nonnull @NotEmpty final String theKey, @Nonnull @NotEmpty final String theValue) {
        super(theKey, theValue);
    }

    /** {@inheritDoc} */
    @Override
    public boolean equals(Object other) {
        if (other == null) {
            return false;
        }

        if (this == other) {
            return true;
        }

        if (other instanceof ShibHeaderPrincipal) {
            return getKey().equals(((ShibHeaderPrincipal) other).getKey())
                    && getValue().equals(((ShibHeaderPrincipal) other).getValue());
        }

        return false;
    }
    
    /** {@inheritDoc} */
    @Override
    public int hashCode() {
        return super.hashCode();
    }

    /** {@inheritDoc} */
    @Override
    public ShibHeaderPrincipal clone() throws CloneNotSupportedException {
        return (ShibHeaderPrincipal) super.clone();
    }
}