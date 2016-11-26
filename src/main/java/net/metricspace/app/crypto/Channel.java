package net.metricspace.app.crypto;

import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.SecureRandom;
import java.util.function.Function;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.SkippingStreamCipher;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.util.Arrays;

import net.metricspace.app.data.Representable;

/**
 * <p>Authenticated symmetric-encryption stream protocol wrapper.
 * {@code Channel}s are a base primitive used in the implementation of
 * other primitives.  Unlike {@code Box}es, which use one-shot keys,
 * {@code Channel}s can use the same {@code Key} to encrypt any number
 * of {@code Message}s.
 *
 * <p>The implementation of {@code Channel}s utilizes the ChaCha20
 * cipher with the Poly1305 MAC.  A global position is kept, which
 * must be supplied to encrypt and decrypt messages.  This position is
 * advanced by the number of bytes of ciphertext encrypted.  It is
 * also used to derive the MAC key for a given message.  {@code
 * Messages} must never overlap in their position ranges.  The {@code
 * Channel} API is specifically designed to prevent this sort of
 * misuse.
 *
 * <p>{@code Channel}s do <em>not</em> keep any record of their {@code
 * Message}s; they only keep the information needed to decrypt any
 * {@code Message} and produce new {@code Message}s.
 */
abstract class Channel {

    /**
     * Size of cipher keys.
     */
    protected static final int CIPHER_KEY_SIZE = 32;

    /**
     * Size of cipher initialization vectors.
     */
    protected static final int IV_SIZE = 12;

    /**
     * Size of MAC keys.
     */
    protected static final int MAC_KEY_SIZE = 32;

    /**
     * Size of MAC codes.
     */
    protected static final int MAC_SIZE = new Poly1305().getMacSize();


    /**
     * The {@code Key} material used to encrypt and decrypt {@code
     * Message}s.
     */
    private final Key key;

    /**
     * Current position.
     */
    private long pos = 0;

    /**
     * Key material used in a {@code Channel}.  This consists of a
     * cipher key, an IV, and a base MAC key used to generate MAC keys
     * for each {@code Message} in the {@code Channel}.
     */
    public static class Key
        implements Representable{
        private static final int CIPHER_KEY_OFFSET = 0;
        private static final int MAC_BASE_KEY_OFFSET =
            CIPHER_KEY_OFFSET + CIPHER_KEY_SIZE;
        private static final int IV_OFFSET =
            MAC_BASE_KEY_OFFSET + MAC_KEY_SIZE;
        private static final int TOTAL_SIZE =
            CIPHER_KEY_SIZE + MAC_KEY_SIZE + IV_SIZE;

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
                                        data, IV_OFFSET, IV_SIZE);
        }

        /**
         * Get the {@code org.bouncycastle.cipher.CipherParameters}
         * for the mac.
         *
         * @param cipher Cipher to use to compute the MAC key.
         * @return The {@code org.bouncycastle.cipher.CipherParameters}
         *         to use with the mac.
         */
        private CipherParameters macParameters(final StreamCipher cipher) {
            final byte[] mackey = new byte[MAC_KEY_SIZE];

            cipher.processBytes(data, MAC_BASE_KEY_OFFSET,
                                MAC_KEY_SIZE, mackey, 0);

            return new KeyParameter(mackey, MAC_BASE_KEY_OFFSET, MAC_KEY_SIZE);
        }

        /**
         * Get a {@code org.bouncycastle.crypto.SkippingStreamCipher}
         * instance using this {@code Key} for encryption.  We seek
         * forward to the current position of
         *
         * @param pos The position to which to seek the stream cipher.
         * @return A {@code org.bouncycastle.crypto.SkippingStreamCipher}
         *         instance for encrypting a single
         *         payload.
         */
        SkippingStreamCipher encryptCipher(final long pos) {
            final SkippingStreamCipher out = new ChaCha7539Engine();

            out.init(true, cipherParameters());
            out.seekTo(pos);

            return out;
        }

        /**
         * Get a {@code org.bouncycastle.crypto.SkippingStreamCipher}
         * instance using this {@code Key} for decryption.  Note that
         * this may only be used to decrypt a single payload.
         *
         * @param pos The position to which to seek the stream cipher.
         * @return A {@code org.bouncycastle.crypto.SkippingStreamCipher}
         *         instance for encrypting a single
         *         payload.
         */
        SkippingStreamCipher decryptCipher(final long pos) {
            final SkippingStreamCipher out = new ChaCha7539Engine();

            out.init(false, cipherParameters());
            out.seekTo(pos + MAC_KEY_SIZE);

            return out;
        }

        /**
         * Get a {@code org.bouncycastle.crypto.Mac} instance using
         * this {@code Key}.
         *
         * @param cipher Cipher to use to compute the MAC key.
         * @return A {@code org.bouncycastle.crypto.Mac} instance
         *         initialized with this {@code Key}.
         */
        Mac mac(final StreamCipher cipher) {
            final Mac out = new Poly1305();

            out.init(macParameters(cipher));

            return out;
        }

        /**
         * Get a {@code org.bouncycastle.crypto.Mac} instance using
         * this {@code Key}.
         *
         * @param pos The position for which to generate the MAC key.
         * @return A {@code org.bouncycastle.crypto.Mac} instance
         *         initialized with this {@code Key}.
         */
        Mac mac(final long pos) {
            return mac(encryptCipher(pos));
        }
    }

    /**
     * Encrypted messages in a {@code Channel}.  A {@code Message}
     * contains the ciphertext, the MAC code, and the position of the
     * message in the cipher stream.
     */
    public static class Message<T extends Representable>
        extends MessagePayload
        implements Representable {

        /**
         * Basic constructor.  Initializes a {@code Message} directly
         * from its components.
         *
         * @param pos The position of the {@code Message} in the {@code Channel}.
         * @param mac The MAC code.
         * @param ciphertext The ciphertext.
         */
        Message(final long pos,
                final byte[] mac,
                final byte[] ciphertext) {
            this.pos = pos;
            this.mac = mac;
            this.ciphertext = ciphertext;
        }

        /**
         * Factory constructor.
         */
        Message() {
            this(0, null, null);
        }

        /**
         * Read in a {@code Message} from a specified length of the
         * input stream.
         *
         * @param in Stream from which to read the {@code Message}.
         * @param len Number of bytes of ciphertext to read (<em>not</em>
         *            including the MAC or position).
         * @throws java.io.IOException If an IO error occurs.
         * @throws IllegalArgumentException If {@code len <= 0}
         */
        public Message(final DataInputStream in,
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
         * Read in a {@code Message} from the entire rest of the input stream.
         *
         * @param in The stream from which to read.
         * @throws java.io.IOException If an IO error occurs.
         */
        public Message(final DataInputStream in)
            throws IOException {
            this(in, in.available() - MAC_SIZE);
        }

        /**
         * {@inheritDoc}
         */
        protected void read(final DataInputStream in)
            throws IOException {
            pos = in.readLong();
            in.read(mac);
            in.read(ciphertext);
        }

        /**
         * {@inheritDoc}
         */
        public void write(final DataOutputStream out)
            throws IOException {
            out.writeLong(pos);
            out.write(mac);
            out.write(ciphertext);
        }
    }

    /**
     * Initialize a {@code Channel} with the given {@code Key} and position.
     *
     * @param key The {@code Key} to use with this {@code Channel}.
     * @param pos The starting position of the {@code Channel}.
     * @throws IllegalArgumentException If {@code pos < 0}.
     */
    protected Channel(final Key key,
                      final long pos)
        throws IllegalArgumentException {
        if (pos >= 0) {
            this.key = key;
            this.pos = pos;
        } else {
            throw new IllegalArgumentException("Invalid position " + size);
        }
    }

    /**
     * Initialize a {@code Channel} with the given {@code Key}.
     *
     * @param key The {@code Key} to use with this {@code Channel}.
     */
    protected Channel(final Key key) {
        this(key, 0);
    }

    /**
     * <p>Reserve space in the stream for a message.  This is made
     * public in order to allow for external implementations to create
     * {@code Message}s in this {@code Channel}.
     *
     * @param size The size of the message (not including the MAC).
     * @return The position to use when initializing ciphers and MACs
     *         for the message.
     * @throws IllegalArgumentException If {@code size <= 0}.
     */
    public long reservePosition(final int size)
        throws IllegalArgumentException {
        if (size > 0) {
            final long out = pos;

            pos += MAC_KEY_SIZE + size;

            return out;
        } else {
            throw new IllegalArgumentException("Invalid message size " + size);
        }
    }

    /**
     * Create an encrypted {@code Message} containing an object's representation.
     *
     * @param <T> The type of data being encrypted.
     * @param data The object to encrypt.
     * @return A {@code Message} containing an encrypted
     *          representation of {@code data}.
     * @throws java.io.IOException If an IO error occurs.
     */
    public <T extends Representable> Message<T> encryptMessage(final T data)
        throws IOException {
        final byte[] bytes = data.bytes();
        final int len = bytes.length;
        final long pos = reservePosition(len);
        final StreamCipher cipher = key.encryptCipher(pos);
        final Mac macalg = key.mac(cipher);
        final byte[] ciphertext = new byte[len];
        final byte[] mac = new byte[MAC_SIZE];
        final byte[] extra = new byte[8];

        // Encrypt the data
        cipher.processBytes(bytes, 0, len, ciphertext, 0);
        // Calculate the MAC
        TlsUtils.writeUint64(pos, extra, 0);
        macalg.update(ciphertext, 0, len);
        macalg.update(extra, 0, extra.length);
        macalg.doFinal(mac, 0);

        return new Message(pos, mac, ciphertext);
    }

    /**
     * Decrypt a {@code Message} in this {@code Channel}.  This
     * attempts to decrypt a {@code Message} using the {@code Key} for
     * this {@code Channel}.  If the {@code Message} does not
     * originate from this {@code Channel} or if the message was
     * tampered with in some way, then the message authentication will
     * fail, resulting in a {@code IntegrityCheckException} being
     * thrown.
     *
     * @param <T> The type of data contained in the {@code Message}.
     * @param msg The {@code Message} to decrypt.
     * @param read The {@code java.util.function.Function} to use to
     *             decode the binary data.
     * @return The decrypted {@code T}.
     * @throws net.metricspace.app.crypto.IntegrityCheckException
               If message authentication fails.
     * @throws java.io.IOException If an IO error occurs.
     */
    public <T extends Representable>
        T decryptMessage(final Message<T> msg,
                         Function<DataInputStream, T> read)
        throws IOException,
               IntegrityCheckException {
        final long pos = msg.getPos();
        final byte[] ciphertext = msg.getCiphertext();
        final byte[] mac = msg.getMac();
        final int len = ciphertext.length;
        final Mac macalg = key.mac(pos);
        final byte[] extra = new byte[8];
        final byte[] actual = new byte[MAC_SIZE];

        // Calculate the MAC
        TlsUtils.writeUint64(pos, extra, 0);
        macalg.update(ciphertext, 0, len);
        macalg.update(extra, 0, extra.length);
        macalg.doFinal(actual, 0);

        // Check for equality
        if (Arrays.constantTimeAreEqual(mac, actual)) {
            // If the MAC checks out, decrypt the ciphertext
            final byte[] plaintext = new byte[len];
            final StreamCipher cipher = key.decryptCipher(pos);

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
    }
}
