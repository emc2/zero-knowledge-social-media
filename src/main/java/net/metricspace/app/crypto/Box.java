package net.metricspace.app.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.SecureRandom;
import java.util.function.Function;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

import net.metricspace.app.data.Representable;

/**
 * Authenticated symmetric encryption primitive.  {@code Box}es are a
 * wrapper for symmetric encryption with authentication with
 * single-use keys.  The {@code Box} API is specifically designed to
 * prevent the reuse of {@code Key}s.
 */
public class Box<T extends Representable>
    extends BoxPayload
    implements Representable {

    private static final int MAC_SIZE = new Poly1305().getMacSize();

    /**
     * Key material for a {@code Box}.  These keys are <em>not</em> reusable
     * with multiple {@code Box}es; both Poly1305 as well as nonces for the
     * ChaCha20 cipher cannot be safely reused.
     */
    public static final class Key
        implements Representable {
        private static final int CIPHER_KEY_OFFSET = 0;
        private static final int CIPHER_KEY_SIZE = 32;
        private static final int MAC_KEY_OFFSET =
            CIPHER_KEY_OFFSET + CIPHER_KEY_SIZE;
        private static final int MAC_KEY_SIZE = 32;
        private static final int NONCE_OFFSET = MAC_KEY_OFFSET + MAC_KEY_SIZE;
        private static final int NONCE_SIZE = 12;
        private static final int TOTAL_SIZE =
            CIPHER_KEY_SIZE + MAC_KEY_SIZE + NONCE_SIZE;

        private final byte[] data = new byte[TOTAL_SIZE];

        /**
         * Read a {@code Key} in from a stream.
         *
         * @param in The stream from which to read.
         * @throws java.io.IOException If an IO error occurs.
         */
        public Key(final DataInputStream in)
            throws IOException {
            read(in);
        }

        /**
         * Generate a {@code Key} from a given {@code
         * java.security.SecureRandom} instance.
         *
         * @param rand The random source to use.
         */
        Key(final SecureRandom rand) {
            rand.nextBytes(data);
        }

        /**
         * {@inheritDoc}
         */
        void read(final DataInputStream in) throws IOException {
            in.read(data);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void write(final DataOutputStream out) throws IOException {
            out.write(data);
        }

        /**
         * Get the {@code org.bouncycastle.cipher.CipherParameters}
         * for the cipher.
         *
         * @return The {@code org.bouncycastle.cipher.CipherParameters}
         *         to use with the cipher.
         */
        private CipherParameters cipherParameters() {
            return new ParametersWithIV(new KeyParameter(data, CIPHER_KEY_OFFSET,
                                                         CIPHER_KEY_SIZE),
                                        data, NONCE_OFFSET, NONCE_SIZE);
        }

        /**
         * Get the {@code org.bouncycastle.cipher.CipherParameters}
         * for the mac.
         *
         * @return The {@code org.bouncycastle.cipher.CipherParameters}
         *         to use with the mac.
         */
        private CipherParameters macParameters() {
            return new KeyParameter(data, MAC_KEY_OFFSET, MAC_KEY_SIZE);
        }

        /**
         * Get a {@code org.bouncycastle.crypto.StreamCipher} instance
         * using this {@code Key} for encryption.  Note that this may
         * only be used to encrypt a single payload.
         *
         * @return A {@code org.bouncycastle.crypto.StreamCipher}
         *         instance for encrypting a single
         *         payload.
         */
        StreamCipher encryptCipher() {
            final StreamCipher out = new ChaCha7539Engine();

            out.init(true, cipherParameters());

            return out;
        }

        /**
         * Get a {@code org.bouncycastle.crypto.StreamCipher} instance
         * using this {@code Key} for decryption.  Note that this may
         * only be used to decrypt a single payload.
         *
         * @return A {@code org.bouncycastle.crypto.StreamCipher}
         *         instance for encrypting a single
         *         payload.
         */
        StreamCipher decryptCipher() {
            final StreamCipher out = new ChaCha7539Engine();

            out.init(false, cipherParameters());

            return out;
        }

        /**
         * Get a {@code org.bouncycastle.crypto.Mac} instance using
         * this {@code Key}.
         *
         * @return A {@code org.bouncycastle.crypto.Mac} instance
         *         initialized with this {@code Key}.
         */
        Mac mac() {
            final Mac out = new Poly1305();

            out.init(macParameters());

            return out;
        }

        @Override
        public boolean equals(final Object other) {
            if (other instanceof Key) {
                return equals((Key)other);
            } else {
                return false;
            }
        }

        public boolean equals(final Key other) {
            return java.util.Arrays.equals(data, other.data);
        }
    }

    /**
     * Create an empty {@code Box}, containing nothing.
     */
    public Box() {}

    /**
     * Read in a {@code Box} from a specified length of the input stream.
     *
     * @param in Stream from which to read ciphertext.
     * @param len Number of bytes of ciphertext to read (<em>not</em>
     *            including the MAC).
     * @throws java.io.IOException If an IO error occurs.
     * @throws IllegalArgumentException If {@code len <= 0}
     */
    public Box(final DataInputStream in,
               final int len)
        throws IOException,
               IllegalArgumentException {
        if (0 < len) {
            this.ciphertext = new byte[len];
            this.mac = new byte[MAC_SIZE];
            read(in);
        } else {
            throw new IllegalArgumentException("Invalid ciphertext length " +
                                               len);
        }
    }

    /**
     * Read in a {@code Box} from the entire rest of the input stream.
     *
     * @param in The stream from which to read.
     * @throws java.io.IOException If an IO error occurs.
     */
    public Box(final DataInputStream in)
        throws IOException {
        this(in, in.available() - MAC_SIZE);
    }

    /**
     * Lock data in a {@code Box} and produce a {@code Key} which
     * unlocks it.
     *
     * @param rand The random source to use to generate the key.
     * @param data The data to lock in the {@code Box}.
     * @return The {@code Key} which unlocks this {@code Box}.
     * @throws java.io.IOException If an IO error occurs.
     * @throws java.lang.IllegalStateException If the {@code Box} is not empty.
     */
    public Key lock(final SecureRandom rand,
                    final T data)
        throws IOException,
               IllegalStateException {
        // Check that the Box is empty
        if (ciphertext == null && mac == null) {
            // Get the algorithms
            final Key key = new Key(rand);
            final Mac macalg = key.mac();
            final StreamCipher cipher = key.encryptCipher();
            // Convert the data to plaintext bytes
            final byte[] plaintext = data.bytes();
            final int len = plaintext.length;

            // Encrypt the plaintext
            ciphertext = new byte[len];
            cipher.processBytes(plaintext, 0, len, ciphertext, 0);
            // Calculate the MAC code
            macalg.update(ciphertext, 0, len);
            mac = new byte[MAC_SIZE];
            macalg.doFinal(mac, 0);

            return key;
        } else if (ciphertext != null && mac != null) {
            // Throw an exception if the box already contains something
            throw new IllegalStateException("Cannot lock a non-empty Box");
        } else {
            throw new IllegalStateException("Inconsistent Box state");
        }
    }

    /**
     * Unlock a {@code Box} using a {@code Key}.  This attempts to
     * unlock a {@code Box} using the given {@code Key}.  If the wrong
     * {@code Key} is given, or if the message was tampered with in
     * some way, then the message authentication will fail, resulting
     * in a {@code IntegrityCheckException} being thrown.
     *
     * @param key The {@code Key} to use for decryption.
     * @param read The {@code java.util.function.Function} to use to
     *             decode the binary data.
     * @return The decrypted {@code T}.
     * @throws net.metricspace.app.crypto.IntegrityCheckException
               If message authentication fails.
     * @throws java.io.IOException If an IO error occurs.
     * @throws java.lang.IllegalStateException If the {@code Box} is empty.
     */
    public T unlock(final Key key,
                    Function<DataInputStream, T> read)
        throws IntegrityCheckException,
               IOException,
               IllegalStateException {
        // Check that the box contains something
        if (ciphertext != null && mac != null) {
            // First check the MAC
            final Mac macalg = key.mac();
            final int len = ciphertext.length;
            final byte[] actual = new byte[MAC_SIZE];

            macalg.update(ciphertext, 0, len);
            macalg.doFinal(actual, 0);

            // Check for equality
            if (Arrays.constantTimeAreEqual(mac, actual)) {
                // If the MAC checks out, decrypt the ciphertext
                final byte[] plaintext = new byte[len];
                final StreamCipher cipher = key.decryptCipher();

                cipher.processBytes(ciphertext, 0, len, plaintext, 0);

                // Now convert the plaintext bytes back into an object
                try(final ByteArrayInputStream bytes =
                    new ByteArrayInputStream(plaintext);
                    final DataInputStream in =
                    new DataInputStream(bytes)) {
                    return read.apply(in);
                }
            } else {
                // If the MAC check fails, throw an exception
                throw new IntegrityCheckException();
            }
        } else if (ciphertext == null && mac == null) {
            // If the box is empty, throw an exception
            throw new IllegalStateException("Cannot unlock an empty Box");
        } else {
            throw new IllegalStateException("Inconsistent Box state");
        }
    }

    /**
     * Get the number of bytes of ciphertext.
     *
     * @return The length of the ciphertext in bytes.
     * @throws IllegalStateException If the {@code Box} is empty.
     */
    public int ciphertextSize() {
        if (ciphertext != null) {
            return ciphertext.length;
        } else {
            throw new IllegalStateException("Box is empty");
        }
    }

    /**
     * Get the number of bytes of the MAC.
     *
     * @return The length of the MAC in bytes.
     * @throws IllegalStateException If the {@code Box} is empty.
     */
    public int macSize() {
        if (mac != null) {
            return mac.length;
        } else {
            throw new IllegalStateException("Box is empty");
        }
    }

    /**
     * Read in raw ciphertext.
     *
     * @param in The stream from which to read.
     * @throws java.io.IOException If an error occurs reading from {@code in}.
     */
    protected void read(final DataInputStream in)
        throws IOException {
        in.read(mac);
        in.read(ciphertext);
    }

    /**
     * Write out raw ciphertext.
     *
     * @param out The stream to which to write.
     * @throws java.io.IOException If an error occurs writing to {@code out}.
     */
    @Override
    public void write(final DataOutputStream out)
        throws IOException {
        out.write(mac);
        out.write(ciphertext);
    }
}
