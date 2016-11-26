package net.metricspace.app.data;

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;

/**
 * Interface for things that can be serialized as raw binary.  This is
 * essentially a parallel of {@code java.io.Serializable} that speaks
 * only in raw binary, without any additional formatting.  This is
 * used as the interface for things that can be wrapped in the crypto
 * primitives in {@code net.metricspace.app.crypto}
 *
 * @see java.io.Serializable
 * @see net.metricspace.app.crypto
 */
public interface Representable {
    /**
     * Write out the state of the object to the given stream.
     *
     * @param out The stream to which to write.
     * @throws java.io.IOException If an error occurs writing to {@code out}.
     */
    public void write(final DataOutputStream out) throws IOException;

    /**
     * Get a {@code byte} array representing this object.
     *
     * @return A {@code byte} array representing the object.
     * @throws java.io.IOException If an IO error occurs.
     */
    public default byte[] bytes()
        throws IOException {
        try(final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            final DataOutputStream data = new DataOutputStream(bytes)) {
            write(data);

            return bytes.toByteArray();
        }
    }
}
