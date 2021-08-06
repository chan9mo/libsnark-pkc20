package java_test;

import java.math.BigInteger;
import java.util.Vector;
import java_test.GroupElement;
import org.bouncycastle.pqc.math.linearalgebra.IntegerFunctions;

@SuppressWarnings("unused")
public class Curve25519{
    private final int BIT_WIDTH = 254;
    private final BigInteger FIELD_PRIME = GroupElement.FIELD_PRIME;
    private final BigInteger CURVE_ORDER = GroupElement.CURVE_ORDER;
    private final BigInteger SUBGROUP_ORDER = GroupElement.SUBGROUP_ORDER;
    private final BigInteger COEFF_A = new BigInteger("126932");

    private final AffinePoint pt;
    private final Vector<String> snark_input_list;
    private final boolean make_snarkinput;

    public Curve25519(AffinePoint p1, boolean make_snarkinput){
        this.pt = new AffinePoint(p1);

        this.make_snarkinput = make_snarkinput;
        if(this.make_snarkinput)
            snark_input_list = new Vector<>();
        else
            snark_input_list = null;
    }

    public Curve25519(BigInteger px, boolean isMatch_ressol, boolean make_snarkinput){
        this.pt = new AffinePoint();
        this.pt.x = px;
        this.pt.y = isMatch_ressol ? computeYCoordinate(px): (computeYCoordinate(px).negate()).mod(FIELD_PRIME);

        this.make_snarkinput = make_snarkinput;
        if(this.make_snarkinput)
            snark_input_list = new Vector<>();
        else
            snark_input_list = null;
    }
    public Curve25519(String pxHex, boolean isMatch_ressol, boolean make_snarkinput){
        this.pt = new AffinePoint();
        this.pt.x = new BigInteger(pxHex, 16);
        this.pt.y = isMatch_ressol ? computeYCoordinate(this.pt.x): (computeYCoordinate(this.pt.x).negate()).mod(FIELD_PRIME);

        this.make_snarkinput = make_snarkinput;
        if(this.make_snarkinput)
            snark_input_list = new Vector<>();
        else
            snark_input_list = null;
    }

    
    public Curve25519(String px, String py, boolean make_snarkinput){
        this.pt = new AffinePoint(px, py);

        this.make_snarkinput = make_snarkinput;
        if(this.make_snarkinput)
            snark_input_list = new Vector<>();
        else
            snark_input_list = null;
    }

    private Curve25519(AffinePoint p1, boolean make_snarkinput, Vector<String> List){
        this.pt = new AffinePoint(p1);
        this.make_snarkinput = make_snarkinput;
        this.snark_input_list = List;
    }

    public Curve25519 mul(BigInteger exp)
    {
        BigInteger[] secretBits = makesecretbits(exp);
        AffinePoint[] baseTable = preprocess(this.pt, secretBits);

        AffinePoint new_p = multiply(baseTable, secretBits);

        return new Curve25519(new_p, this.make_snarkinput, this.snark_input_list);
    }

    public Curve25519 add(Curve25519 ECC2)
    {
        AffinePoint new_p;
        if(ECC2.getPoint().equals(this.pt))
            new_p = doubleAffinePoint(this.pt);
        else
            new_p = addAffinePoints(this.pt, ECC2.getPoint());
    
        if(make_snarkinput) {
            String tmp = this.snark_input_list.remove(this.snark_input_list.size() - 1);
            this.snark_input_list.addAll(ECC2.getSnark_Vector());
            this.snark_input_list.add(tmp);
        }
        return new Curve25519(new_p, this.make_snarkinput, this.snark_input_list);
    }

    public Curve25519 sub(Curve25519 ECC2)
    {
        AffinePoint new_p = subAffinePoints(this.pt, ECC2.getPoint());
        return new Curve25519(new_p, this.make_snarkinput, this.snark_input_list);
    }

    public AffinePoint getPoint(){
        return new AffinePoint(this.pt);
    }

    private AffinePoint multiply(AffinePoint[] precomputedTable, BigInteger[] secretBits) {
        AffinePoint result = new AffinePoint(precomputedTable[secretBits.length]);
        for (int j = secretBits.length - 1; j >= 0; j--) {
            AffinePoint tmp = addAffinePoints(result, precomputedTable[j]);
            BigInteger isOne = secretBits[j];
            result.x = (result.x.add(isOne.multiply(tmp.x.subtract(result.x)))).mod(FIELD_PRIME);
            result.y = (result.y.add(isOne.multiply(tmp.y.subtract(result.y)))).mod(FIELD_PRIME);
        }
        result = subAffinePoints(result, precomputedTable[secretBits.length]);

        return result;
    }

    private AffinePoint addAffinePoints(AffinePoint p1, AffinePoint p2) {
        BigInteger two = new BigInteger("2");
        BigInteger diffY = p1.y.subtract(p2.y).mod(FIELD_PRIME);
        BigInteger diffX = p1.x.subtract(p2.x).mod(FIELD_PRIME);
        BigInteger q = FieldDivision(diffY, diffX);

        BigInteger q2 = q.multiply(q);
        BigInteger q3 = q2.multiply(q);
        BigInteger newX = q2.subtract(COEFF_A).subtract(p1.x).subtract(p2.x).mod(FIELD_PRIME);
        BigInteger newY = p1.x.multiply(two).add(p2.x).add(COEFF_A).multiply(q).subtract(q3).subtract(p1.y).mod(FIELD_PRIME);
        return new AffinePoint(newX, newY);
    }

    private AffinePoint subAffinePoints(AffinePoint p1, AffinePoint p2) {
        BigInteger two = new BigInteger("2");
        BigInteger diffY = p1.y.add(p2.y).mod(FIELD_PRIME);
        BigInteger diffX = p1.x.subtract(p2.x).mod(FIELD_PRIME);
        BigInteger q = FieldDivision(diffY, diffX);

        BigInteger q2 = q.multiply(q);
        BigInteger q3 = q2.multiply(q);
        BigInteger newX = q2.subtract(COEFF_A).subtract(p1.x).subtract(p2.x).mod(FIELD_PRIME);
        BigInteger newY = p1.x.multiply(two).add(p2.x).add(COEFF_A).multiply(q).subtract(q3).subtract(p1.y).mod(FIELD_PRIME);

        return new AffinePoint(newX, newY);
    }

    public BigInteger FieldDivision(BigInteger a, BigInteger b){
        BigInteger c = (a.multiply(b.modInverse(FIELD_PRIME)).mod(FIELD_PRIME));

        if(make_snarkinput) {
            snark_input_list.add(c.toString(16));
        }
        return c;
    }

    private boolean isValidPointOnEC(BigInteger x, BigInteger y) {
        BigInteger ySqr = y.multiply(y).mod(FIELD_PRIME);
        BigInteger xSqr = x.multiply(x).mod(FIELD_PRIME);
        BigInteger xCube = xSqr.multiply(x).mod(FIELD_PRIME);
        return ySqr.equals( xCube.add(xSqr.multiply(COEFF_A)).add(x).mod(FIELD_PRIME));
    }

    private AffinePoint doubleAffinePoint(AffinePoint p) {
        BigInteger three = new BigInteger("3");
        BigInteger two = new BigInteger("2");
        BigInteger x_2 = p.x.multiply(p.x).mod(FIELD_PRIME);
        BigInteger l1 = FieldDivision(x_2.multiply(three).add(p.x.multiply(COEFF_A).multiply(two)).add(BigInteger.ONE), p.y.multiply(two));
        BigInteger l2 = l1.multiply(l1);
        BigInteger newX = l2.subtract(COEFF_A).subtract(p.x).subtract(p.x);
        BigInteger newY = p.x.multiply(three).add(COEFF_A).subtract(l2).multiply(l1).subtract(p.y);

        return new AffinePoint(newX.mod(FIELD_PRIME), newY.mod(FIELD_PRIME));
    }

    private AffinePoint[] preprocess(AffinePoint p, BigInteger[] secretBits) {
        AffinePoint[] precomputedTable = new AffinePoint[secretBits.length+1];

        precomputedTable[0] = p;
        for (int j = 1; j <= secretBits.length; j += 1) {
            precomputedTable[j] = doubleAffinePoint(precomputedTable[j - 1]);
        }
        return precomputedTable;
    }

    private BigInteger computeYCoordinate(BigInteger x) {
        BigInteger xSqred = (x.multiply(x)).mod(FIELD_PRIME);
        BigInteger xCubed = (xSqred.multiply(x)).mod(FIELD_PRIME);
        BigInteger ySqred = (xCubed.add(COEFF_A.multiply(xSqred)).add(x)).mod(FIELD_PRIME);
        return (IntegerFunctions.ressol(ySqred, FIELD_PRIME)).mod(FIELD_PRIME);
    }

    private BigInteger[] makesecretbits(BigInteger input){
        BigInteger[] qr;

        qr = input.divideAndRemainder(SUBGROUP_ORDER);

        if(make_snarkinput) {
            snark_input_list.add(qr[1].toString(16));
            snark_input_list.add(qr[0].toString(16));
        }

        //BigInteger[] temp1 = zeroPadBigIntegers(split(qr[1]));
        //BigInteger[] output = new BigInteger[BIT_WIDTH];
        //System.arraycopy(temp1, 0, output, 0, temp1.length);

        BigInteger[] temp2 = getBitSplit(qr[1], BIT_WIDTH);
        return temp2;
    }

    private BigInteger[] getBitSplit(BigInteger in, int bitWidth) {
        BigInteger[] out = new BigInteger[bitWidth];
        byte[] byte_arr = in.toByteArray();
        byte[] byte_tmp = new byte[1];

        int rem = in.bitLength() > bitWidth ? bitWidth%8 : in.bitLength()%8;
        int len = in.bitLength() > bitWidth ? bitWidth/8 : in.bitLength()/8;
        int offset = (rem == 0 ? 0 : 1) + (byte_arr[0] == 0 ? 1 : 0);
        int idx = 0;

        for (int j = len; j >= offset; j--) {
            for (int i = 0; i < 8; i++) {
                byte_tmp[0] = (byte) ((byte_arr[j] >> i) & 0x01);
                out[idx++] = new BigInteger(1, byte_tmp);
            }
        }

        for (int i = 0; i < rem; i++) {
            byte_tmp[0] = (byte) ((byte_arr[0] >> i) & 0x01);
            out[idx++] = new BigInteger(1, byte_tmp);
        }

        for (; idx < bitWidth; idx++)
            out[idx] = BigInteger.ZERO;

        return out;
    }

    public boolean isMatch_ressol(){
        return (computeYCoordinate(this.pt.x)).equals((this.pt.y));
    }

    private Vector<String> getSnark_Vector(){
        return this.snark_input_list;
    }

    public Vector<String> getSnarkTable(){
        if(!make_snarkinput)
            return null;

        return new Vector<>(this.snark_input_list);
    }

    public boolean equals(Curve25519 a){
        return (this.pt).equals( a.getPoint() );
    }
}
