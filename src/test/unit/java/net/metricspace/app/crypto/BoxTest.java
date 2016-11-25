package net.metricspace.app.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Arrays;

import org.testng.Assert;
import org.testng.annotations.Test;

import net.metricspace.app.data.Representable;

public class BoxTest {

    private static class TestData implements Representable {
        private final byte[] data;

        public TestData(final byte[] data) {
            this.data = data;
        }

        public static TestData read(final InputStream in) {
            try {
                final byte[] data = new byte[in.available()];

                in.read(data);

                return new TestData(data);
            } catch(final IOException e) {
                return null;
            }
        }

        @Override
        public boolean equals(final Object other) {
            if (other instanceof TestData) {
                return equals((TestData)other);
            } else {
                return false;
            }
        }

        public boolean equals(final TestData other) {
            return Arrays.equals(data, other.data);
        }

        @Override
        public void write(final OutputStream out)
            throws IOException {
            out.write(data);
        }
    }

    @Test
    public void testLockUnlock()
        throws IOException,
               IntegrityCheckException {
        final TestData expected =
            new TestData(new byte[] { 0x42, 0x21, 0x13, 0x69 });
        final Box<TestData> box = new Box<>();
        final Box.Key key = box.lock(new SecureRandom(), expected);
        final TestData actual = box.unlock(key, TestData::read);

        Assert.assertEquals(expected, actual);
    }

    @Test(expectedExceptions = IllegalStateException.class)
    public void testBadUnlock()
        throws IOException,
               IntegrityCheckException {
        final TestData expected =
            new TestData(new byte[] { 0x42, 0x21, 0x13, 0x69 });
        final Box<TestData> box = new Box<>();
        final Box.Key key = box.lock(new SecureRandom(), expected);
        final Box<TestData> badbox = new Box<>();

        badbox.unlock(key, TestData::read);
    }

    @Test(expectedExceptions = IllegalStateException.class)
    public void testBadLock()
        throws IOException,
               IntegrityCheckException {
        final TestData expected =
            new TestData(new byte[] { 0x42, 0x21, 0x13, 0x69 });
        final Box<TestData> box = new Box<>();

        box.lock(new SecureRandom(), expected);
        box.lock(new SecureRandom(), expected);
    }

    @Test
    public void testLockWriteReadUnlock()
        throws IOException,
               IntegrityCheckException {
        final TestData expected =
            new TestData(new byte[] { 0x42, 0x21, 0x13, 0x69 });
        final Box<TestData> box = new Box<>();
        final Box.Key key = box.lock(new SecureRandom(), expected);
        final byte[] boxbytes = box.bytes();
        final Box<TestData> newbox =
            new Box<>(new ByteArrayInputStream(boxbytes));
        final TestData actual = newbox.unlock(key, TestData::read);

        Assert.assertEquals(expected, actual);
    }

    @Test(expectedExceptions = IntegrityCheckException.class)
    public void testIntegrityCheck()
        throws IOException,
               IntegrityCheckException {
        final TestData expected =
            new TestData(new byte[] { 0x42, 0x21, 0x13, 0x69 });
        final Box<TestData> box = new Box<>();
        final Box.Key key = box.lock(new SecureRandom(), expected);
        final byte[] boxbytes = box.bytes();

        // Corrupt one byte of the message
        boxbytes[boxbytes.length - 1] ^= 0x10;

        final Box<TestData> newbox =
            new Box<>(new ByteArrayInputStream(boxbytes));
        final TestData actual = newbox.unlock(key, TestData::read);

        Assert.assertEquals(expected, actual);
    }

    @Test
    public void testLockWriteExtraReadUnlock()
        throws IOException,
               IntegrityCheckException {
        final TestData expected =
            new TestData(new byte[] { 0x42, 0x21, 0x13, 0x69 });
        final Box<TestData> box = new Box<>();
        final Box.Key key = box.lock(new SecureRandom(), expected);
        final byte[] boxbytes = box.bytes();
        final byte[] extrabytes = Arrays.copyOf(boxbytes, boxbytes.length + 4);
        final Box<TestData> newbox =
            new Box<>(new ByteArrayInputStream(boxbytes),
                      box.ciphertextSize());
        final TestData actual = newbox.unlock(key, TestData::read);

        Assert.assertEquals(expected, actual);
    }
}
