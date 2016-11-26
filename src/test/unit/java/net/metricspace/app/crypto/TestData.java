package net.metricspace.app.crypto;

import java.io.IOException;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.util.Arrays;

import net.metricspace.app.data.Representable;

class TestData implements Representable {
    private final byte[] data;

    public TestData(final byte[] data) {
        this.data = data;
    }

    public static TestData read(final DataInputStream in) {
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
    public void write(final DataOutputStream out)
        throws IOException {
        out.write(data);
    }
}
