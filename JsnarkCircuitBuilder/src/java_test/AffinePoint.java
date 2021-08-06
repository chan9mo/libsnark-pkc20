package java_test;

import java.math.BigInteger;

public class AffinePoint {
    public BigInteger x;
    public BigInteger y;

    public AffinePoint() {
        this.x = new BigInteger("0");
        this.y = new BigInteger("0");
    }

    public AffinePoint(String x, String y) {
        this.x = new BigInteger(x,16);
        this.y = new BigInteger(y,16);
    }

    public AffinePoint(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }

    public AffinePoint(AffinePoint p) {
        this.x = p.x;
        this.y = p.y;
    }

    public String toString(int radix) {
        return x.toString(radix) + " " + y.toString(radix);
    }

    public boolean equals(AffinePoint p){
        return (p.x.equals(this.x))&(p.y.equals(this.y));
    }
}
