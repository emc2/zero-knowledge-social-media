package net.metricspace.app.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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

import net.metricspace.app.crypto.jaxb.BoxPayload;
import net.metricspace.app.data.Representable;

/**
 * Authenticated symmetric encryption primitive.  Boxes are a wrapper
 * for symmetric encryption with authentication.
 */
public class Box<T extends Representable> extends BoxPayload
    implements Representable {

    private static final int MAC_OFFSET = 0;
    private static final int MAC_SIZE = 16;
    private static final int TEXT_OFFSET = MAC_OFFSET + MAC_SIZE;
    private static final int MIN_CIPHERTEXT_SIZE = TEXT_OFFSET;

    /**
     * Key material for a {@code Box}.  These keys are not reusable
     * with multiple {@code Box}es; both Poly1305 as well as nonces for the
     * ChaCha20 cipher cannot be safely reused with multiple
     * ciphertexts.
     */
    public static class Key implements Representable {
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
        public Key(final InputStream in)
            throws IOException {
            read(in);
        }

        /**
         * Generate a {@code Key} from a given {@code
         * java.security.SecureRandom} instance.
         *
         * @param rand The random source to use.
         */
        public Key(final SecureRandom rand) {
            rand.nextBytes(data);
        }

        /**
         * {@inheritDoc}
         */
        protected void read(final InputStream in) throws IOException {
            in.read(data);
        }

        /**
         * {@inheritDoc}
         */
        public void write(final OutputStream out) throws IOException {
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
        public StreamCipher encryptCipher() {
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
        public StreamCipher decryptCipher() {
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
        public Mac mac() {
            final Mac out = new Poly1305();

            out.init(macParameters());

            return out;
        }
    }

    /**
     * Default constructor, used by {@code
     * net.metricspace.crypto.jaxb.ObjectFactory}.
     */
    public Box() {}

    /**
     * Read in a {@code Box} from a specified length of the input stream.
     *
     * @param in Stream from which to read ciphertext.
     * @param len Number of bytes of ciphertext to read.
     * @throws java.io.IOException If an IO error occurs.
     */
    public Box(final InputStream in,
               final int len)
        throws CryptoException, IOException {

        if(len > MIN_CIPHERTEXT_SIZE) {
            this.ciphertext = new byte[len];
            read(in);
        } else {
            throw new InvalidFormatException();
        }
    }

    /**
     * Read in a {@code Box} from the entire rest of the input stream.
     *
     * @param in The stream from which to read.
     * @throws java.io.IOException If an IO error occurs.
     */
    public Box(final InputStream in)
        throws CryptoException, IOException {
        this(in, in.available());
    }

    /**
     * Lock data in a {@code Box} and produce a {@code Key} which
     * unlocks it.
     *
     * @param rand The random source to use to generate the key.
     * @param data The data to lock in the {@code Box}.
     * @return The {@code Key} which unlocks this {@code Box}.
     * @throws java.io.IOException If an IO error occurs.
     */
    public Key lock(final SecureRandom rand,
                    final T data)
        throws IOException {
        final Key key = new Key(rand);
        final byte[] plaintext = data.bytes();
        final Mac mac = key.mac();
        final StreamCipher cipher = key.encryptCipher();
        final int len = plaintext.length;

        ciphertext = new byte[len + MAC_SIZE];
        cipher.processBytes(plaintext, 0, len, ciphertext, TEXT_OFFSET);
        mac.update(ciphertext, TEXT_OFFSET, len);
        mac.doFinal(ciphertext, MAC_OFFSET);

        return key;
    }

    /**
     * Unlock a {@code Box} using a {@code Key}.  This attempts to
     * unlock a {@code Box} using the given {@code Key}.  If the wrong
     * {@code Key} is given, or if the message was tampered with in
     * some way, then the message authentication will fail, resulting
     * in a {@code MACFailureException} being thrown.
     *
     * @param key The {@code Key} to use for decryption.
     * @param read The {@code java.util.function.Function} to use to
     *             decode the binary data.
     * @return The decrypted {@code T}.
     * @throws MACFailureException If message authentication fails.
     * @throws java.io.IOException If an IO error occurs.
     */
    public T unlock(final Key key,
                    Function<InputStream, T> read)
        throws CryptoException, IOException {
        final int len = ciphertext.length - MAC_SIZE;
        final Mac mac = key.mac();
        final byte[] expected = Arrays.copyOf(ciphertext, MAC_SIZE);
        final byte[] actual = new byte[MAC_SIZE];

        mac.update(ciphertext, TEXT_OFFSET, len);
        mac.doFinal(actual, MAC_OFFSET);

        if (Arrays.constantTimeAreEqual(expected, actual)) {
            final byte[] plaintext = new byte[len];
            final StreamCipher cipher = key.decryptCipher();

            cipher.processBytes(ciphertext, TEXT_OFFSET, len, plaintext, 0);

            try(final ByteArrayInputStream in =
                new ByteArrayInputStream(plaintext)) {
                return read.apply(in);
            }
        } else {
            throw new MACFailureException();
        }
    }

    /**
     * Read in raw ciphertext.
     *
     * @param in The stream from which to read.
     * @throws java.io.IOException If an error occurs reading from {@code in}.
     */
    protected void read(final InputStream in)
        throws IOException {
        in.read(ciphertext);
    }

    /**
     * Write out raw ciphertext.
     *
     * @param out The stream to which to write.
     * @throws java.io.IOException If an error occurs reading from {@code in}.
     */
    public void write(final OutputStream out)
        throws IOException {
        out.write(ciphertext);
    }

}