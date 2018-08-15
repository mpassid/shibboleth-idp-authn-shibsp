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

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.Principal;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonString;
import javax.json.JsonStructure;
import javax.json.stream.JsonGenerator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;

import net.shibboleth.idp.authn.principal.AbstractPrincipalSerializer;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

/**
 * Base serializer for {@link KeyValuePrincipal}. Based on {@link GenericPrincipalSerializer}.
 *
 * @param <T> The principal type to be serialized.
 */
public abstract class KeyValuePrincipalSerializer<T extends KeyValuePrincipal> 
    extends AbstractPrincipalSerializer<String> {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(KeyValuePrincipalSerializer.class);
    
    /** {@inheritDoc} */
    @Override
    @Nonnull @NotEmpty public String serialize(@Nonnull final Principal principal) throws IOException {
        log.trace("Attempting to serialize name={}", ((KeyValuePrincipal)principal).getName());
        final StringWriter sink = new StringWriter(32);
        final JsonGenerator gen = getJsonGenerator(sink);
        gen.writeStartObject()
            .write(getKeyField(), ((KeyValuePrincipal)principal).getKey())
            .write(getValueField(), ((KeyValuePrincipal)principal).getValue())
            .writeEnd();
        gen.close();
        log.trace("Successfully built serialized principal: {}", sink.toString());
        return sink.toString();
    }
    
    /**
     * Get the field name for the key in the principal.
     * @return The field name for the key in the principal.
     */
    public abstract @Nonnull @NotEmpty String getKeyField();
    
    /**
     * Get the field name for the value in the principal.
     * @return The field name for the value in the principal.
     */
    public abstract @Nonnull @NotEmpty String getValueField();

    /** {@inheritDoc} */
    @Override
    @Nullable public T deserialize(@Nonnull @NotEmpty final String value) throws IOException {
        log.trace("Attempting to deserialize {}", value);
        final JsonReader reader = getJsonReader(new StringReader(value));
        JsonStructure st = null;
        try {
            log.debug("Reading the JSON structure");
            st = reader.read();
        } finally {
            reader.close();
        }
        if (!(st instanceof JsonObject)) {
            log.warn("Could not parse a JSON object from serialized value", value);
            throw new IOException("Found invalid data structure while parsing KeyValuePrincipal");
        }
        log.debug("JSON structure successfully read");
        final JsonString jsonKey = ((JsonObject) st).getJsonString(getKeyField());
        final JsonString jsonValue = ((JsonObject) st).getJsonString(getValueField());
        if (jsonKey != null && jsonValue != null) {
            final String theKey = jsonKey.getString();
            final String theValue = jsonValue.getString();
            if (!Strings.isNullOrEmpty(theKey) && !Strings.isNullOrEmpty(theValue)) {
                return construct(theKey, theValue);
            }
        }
        return null;
    }

    /**
     * Construct a new principal.
     * @param key The key.
     * @param value The value.
     * @return The newly constructed principal.
     */
    public abstract T construct(final String key, final String value);
}
