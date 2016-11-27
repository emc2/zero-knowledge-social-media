package net.metricspace.app.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.DataInputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.testng.Assert;
import org.testng.annotations.Test;

public class ChannelTest {
    private static SecureRandom rand = new SecureRandom();

    private static class TestChannel extends Channel {
        public TestChannel() {
            super(rand);
        }
    }

    @Test
    public void keyWriteRead()
        throws IOException {
        final Channel.Key expected = new Channel.Key(new SecureRandom());
        final byte[] bytes = expected.bytes();
        final Channel.Key actual =
            new Channel.Key(new DataInputStream(new ByteArrayInputStream(bytes)));

        Assert.assertEquals(expected, actual);
    }

    private void doTestEncryptDecrypt(final byte[] data)
        throws IOException,
               IntegrityCheckException {
        final TestData expected = new TestData(data);
        final Channel channel = new TestChannel();
        final Channel.Message<TestData> msg = channel.encryptMessage(expected);
        final TestData actual = channel.decryptMessage(msg, TestData::read);

        Assert.assertEquals(expected, actual);
    }

    @Test
    public void testEncryptDecrypt()
        throws IOException,
               IntegrityCheckException {
        for(int i = 1; i < 256; i++) {
            final byte[] data = new byte[i];

            for(int j = 0; j < i; j++) {
                data[j] = (byte)(j * i);
            }

            doTestEncryptDecrypt(data);
        }
    }

    private void doTestEncryptWriteReadDecrypt(final byte[] data)
        throws IOException,
               IntegrityCheckException {
        final TestData expected = new TestData(data);
        final Channel channel = new TestChannel();
        final Channel.Message<TestData> msg = channel.encryptMessage(expected);
        final byte[] msgbytes = msg.bytes();
        final Channel.Message<TestData> newmsg =
            new Channel.Message<>(new DataInputStream(
                                      new ByteArrayInputStream(msgbytes)));
        final TestData actual = channel.decryptMessage(newmsg, TestData::read);

        Assert.assertEquals(expected, actual);
    }

    @Test
    public void testEncryptWriteReadDecrypt()
        throws IOException,
               IntegrityCheckException {
        for(int i = 1; i < 256; i++) {
            final byte[] data = new byte[i];

            for(int j = 0; j < i; j++) {
                data[j] = (byte)(j * i);
            }

            doTestEncryptWriteReadDecrypt(data);
        }
    }

    private void doTestIntegrityCheck(final byte[] data)
        throws IOException,
               IntegrityCheckException {
        final TestData expected = new TestData(data);
        final Channel channel = new TestChannel();
        final Channel.Message<TestData> msg = channel.encryptMessage(expected);
        final byte[] msgbytes = msg.bytes();

        // Corrupt one byte of the message
        msgbytes[msgbytes.length - 1] ^= 0x10;

        final Channel.Message<TestData> newmsg =
            new Channel.Message<>(new DataInputStream(
                                      new ByteArrayInputStream(msgbytes)));
        final TestData actual = channel.decryptMessage(newmsg, TestData::read);

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

    private void doTestMultiEncryptDecrypt(final List<byte[]> data)
        throws IOException,
               IntegrityCheckException {
        final Channel channel = new TestChannel();
        final List<TestData> expecteds = new ArrayList<>(data.size());
        final List<Channel.Message<TestData>> msgs =
            new ArrayList<>(data.size());

        // Send all the messages first
        for(final byte[] msgdata : data) {
            final TestData expected = new TestData(msgdata);
            final Channel.Message<TestData> msg =
                channel.encryptMessage(expected);

            expecteds.add(expected);
            msgs.add(msg);
        }

        // Now check them
        for(int i = 0; i < data.size(); i++) {
            final TestData expected = expecteds.get(i);
            final Channel.Message<TestData> msg = msgs.get(i);
            final TestData actual = channel.decryptMessage(msg, TestData::read);

            Assert.assertEquals(expected, actual);
        }
    }

    @Test
    public void testMultiEncryptDecrypt()
        throws IOException,
               IntegrityCheckException {
        // Number of messages
        for(int nmsgs = 2; nmsgs < 16; nmsgs++) {
            // Shift factor in size of messages
            for(int shift = 0; shift < nmsgs; shift++) {
                // Size multiple
                for(int mult = 1; mult < 64; mult++) {
                    final List<byte[]> list = new ArrayList<>(nmsgs);

                    for(int i = 0; i < nmsgs; i++) {
                        final int size = (((i + shift) % nmsgs) + 1) * mult;
                        final byte[] data = new byte[size];

                        for(int j = 0; j < size; j++) {
                            data[j] = (byte)(i * j);
                        }

                        list.add(data);
                    }

                    doTestMultiEncryptDecrypt(list);
                }
            }
        }
    }
}
