package net.metricspace.app.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.DataInputStream;
import java.security.SecureRandom;
import java.util.Arrays;

import org.testng.Assert;
import org.testng.annotations.Test;

public class BoxTest {
    private void doTestLockUnlock(final byte[] data)
        throws IOException,
               IntegrityCheckException {
        final TestData expected = new TestData(data);
        final Box<TestData> box = new Box<>();
        final Box.Key key = box.lock(new SecureRandom(), expected);
        final TestData actual = box.unlock(key, TestData::read);

        Assert.assertEquals(expected, actual);
    }

    @Test
    public void testLockUnlock()
        throws IOException,
               IntegrityCheckException {
        for(int i = 1; i < 256; i++) {
            final byte[] data = new byte[i];

            for(int j = 0; j < i; j++) {
                data[j] = (byte)(j * i);
            }

            doTestLockUnlock(data);
        }
    }

    private void doTestBadUnlock(final byte[] data)
        throws IOException,
               IntegrityCheckException {
        final TestData expected = new TestData(data);
        final Box<TestData> box = new Box<>();
        final Box.Key key = box.lock(new SecureRandom(), expected);
        final Box<TestData> badbox = new Box<>();

        badbox.unlock(key, TestData::read);
    }

    @Test(expectedExceptions = IllegalStateException.class)
    public void testBadUnlock()
        throws IOException,
               IntegrityCheckException {
        for(int i = 1; i < 256; i++) {
            final byte[] data = new byte[i];

            for(int j = 0; j < i; j++) {
                data[j] = (byte)(j * i);
            }

            doTestBadUnlock(data);
        }
    }

    private void doTestBadLock(final byte[] data)
        throws IOException,
               IntegrityCheckException {
        final TestData expected = new TestData(data);
        final Box<TestData> box = new Box<>();

        box.lock(new SecureRandom(), expected);
        box.lock(new SecureRandom(), expected);
    }

    @Test(expectedExceptions = IllegalStateException.class)
    public void testBadLock()
        throws IOException,
               IntegrityCheckException {
        for(int i = 1; i < 256; i++) {
            final byte[] data = new byte[i];

            for(int j = 0; j < i; j++) {
                data[j] = (byte)(j * i);
            }

            doTestBadLock(data);
        }
    }

    private void doTestLockWriteReadUnlock(final byte[] data)
        throws IOException,
               IntegrityCheckException {
        final TestData expected = new TestData(data);
        final Box<TestData> box = new Box<>();
        final Box.Key key = box.lock(new SecureRandom(), expected);
        final byte[] boxbytes = box.bytes();
        final Box<TestData> newbox =
            new Box<>(new DataInputStream(new ByteArrayInputStream(boxbytes)));
        final TestData actual = newbox.unlock(key, TestData::read);

        Assert.assertEquals(expected, actual);
    }

    @Test
    public void testLockWriteReadUnlock()
        throws IOException,
               IntegrityCheckException {
        for(int i = 1; i < 256; i++) {
            final byte[] data = new byte[i];

            for(int j = 0; j < i; j++) {
                data[j] = (byte)(j * i);
            }

            doTestLockWriteReadUnlock(data);
        }
    }

    private void doTestIntegrityCheck(final byte[] data)
        throws IOException,
               IntegrityCheckException {
        final TestData expected = new TestData(data);
        final Box<TestData> box = new Box<>();
        final Box.Key key = box.lock(new SecureRandom(), expected);
        final byte[] boxbytes = box.bytes();

        // Corrupt one byte of the message
        boxbytes[boxbytes.length - 1] ^= 0x10;

        final Box<TestData> newbox =
            new Box<>(new DataInputStream(new ByteArrayInputStream(boxbytes)));
        final TestData actual = newbox.unlock(key, TestData::read);

        Assert.assertEquals(expected, actual);
    }

    @Test(expectedExceptions = IntegrityCheckException.class)
    public void testIntegrityCheck()
        throws IOException,
               IntegrityCheckException {
        for(int i = 1; i < 256; i++) {
            final byte[] data = new byte[i];

            for(int j = 0; j < i; j++) {
                data[j] = (byte)(j * i);
            }

            doTestIntegrityCheck(data);
        }
    }

    private void doTestLockWriteExtraReadUnlock(final byte[] data)
        throws IOException,
               IntegrityCheckException {
        final TestData expected = new TestData(data);
        final Box<TestData> box = new Box<>();
        final Box.Key key = box.lock(new SecureRandom(), expected);
        final byte[] boxbytes = box.bytes();
        final byte[] extrabytes = Arrays.copyOf(boxbytes, boxbytes.length + 4);
        final Box<TestData> newbox =
            new Box<>(new DataInputStream(new ByteArrayInputStream(boxbytes)),
                      box.ciphertextSize());
        final TestData actual = newbox.unlock(key, TestData::read);

        Assert.assertEquals(expected, actual);
    }

    @Test
    public void testLockWriteExtraReadUnlock()
        throws IOException,
               IntegrityCheckException {
        for(int i = 1; i < 256; i++) {
            final byte[] data = new byte[i];

            for(int j = 0; j < i; j++) {
                data[j] = (byte)(j * i);
            }

            doTestLockWriteExtraReadUnlock(data);
        }
    }

    @Test
    public void keyWriteRead()
        throws IOException {
        final Box.Key expected = new Box.Key(new SecureRandom());
        final byte[] bytes = expected.bytes();
        final Box.Key actual =
            new Box.Key(new DataInputStream(new ByteArrayInputStream(bytes)));

        Assert.assertEquals(expected, actual);
    }
}
