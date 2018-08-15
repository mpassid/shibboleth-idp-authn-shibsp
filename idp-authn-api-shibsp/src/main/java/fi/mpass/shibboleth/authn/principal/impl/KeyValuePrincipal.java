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

import java.util.StringTokenizer;

import javax.annotation.Nonnull;

import net.shibboleth.idp.authn.principal.CloneablePrincipal;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import com.google.common.base.MoreObjects;

/**
 * This class extends {@link Principal} by dividing the name to key and value with a
 * static separator string.
 */
public abstract class KeyValuePrincipal implements CloneablePrincipal {

    /** The string separating key and value -pair in name. */
    @Nonnull @NotEmpty protected static final String SEPARATOR = "<=>";

    /** The key part of the pair. */
    @Nonnull @NotEmpty private String key;

    /** The value part of the pair. */
    @Nonnull @NotEmpty private String value;

    /**
     * Constructor.
     * 
     * @param theName containing the key and the value, separated by '<=>'
     */
    public KeyValuePrincipal(@Nonnull @NotEmpty final String theName) {
        final StringTokenizer tokenizer = new StringTokenizer(theName, SEPARATOR);
        if (tokenizer.countTokens() != 2) {
            throw new ConstraintViolationException("Incompatible name given, cannot be divided by " + SEPARATOR);
        }
        key = Constraint.isNotNull(StringSupport.trimOrNull(tokenizer.nextToken()), "Key cannot be null or empty");
        value = Constraint.isNotNull(StringSupport.trimOrNull(tokenizer.nextToken()), "Value cannot be null or empty");
    }

    /**
     * Constructor.
     * 
     * @param theKey the key, can not be null or empty
     * @param theValue the value corresponding to the key, can not be null or empty
     */
    public KeyValuePrincipal(@Nonnull @NotEmpty final String theKey, @Nonnull @NotEmpty final String theValue) {
        key = Constraint.isNotNull(StringSupport.trimOrNull(theKey), "Key cannot be null or empty");
        value = Constraint.isNotNull(StringSupport.trimOrNull(theValue), "Value cannot be null or empty");
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull @NotEmpty public String getName() {
        return key + SEPARATOR + value;
    }

    /**
     * Get the key.
     * @return key
     */
    @Nonnull @NotEmpty public String getKey() {
        return key;
    }

    /**
     * Get the value.
     * @return value
     */
    @Nonnull @NotEmpty public String getValue() {
        return value;
    }

    /** {@inheritDoc} */
    @Override
    public int hashCode() {
        return (key + ":" + value).hashCode();
    }

    /** {@inheritDoc} */
    @Override
    public abstract boolean equals(Object other);

    /** {@inheritDoc} */
    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this).add("key", key).add("value", value).toString();
    }

    /** {@inheritDoc} */
    @Override
    public KeyValuePrincipal clone() throws CloneNotSupportedException {
        KeyValuePrincipal copy = (KeyValuePrincipal) super.clone();
        copy.key = key;
        copy.value = value;
        return copy;
    }
}
