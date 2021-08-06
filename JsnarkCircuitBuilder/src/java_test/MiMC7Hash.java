package java_test;

import java.util.Random;
import circuit.operations.Gadget;
//import circuit.structure.BigInteger;

import org.ethereum.crypto.cryptohash.Keccak256;
import java.math.BigInteger;
import java.util.Arrays;

import java_test.GroupElement;

public class MiMC7Hash {
    private BigInteger inputLeft;
    private BigInteger inputRight;
    private BigInteger output;
    /**
     * MiMC specialized for Fr in ALT-BN128, in which the exponent is 7 and 91
     * rounds are used.
     */

    private static Keccak256 keccak256 = new Keccak256(); // Must declared before using _keccak256()
    private static String seedStr = "snplab_CRV_seed";
    private static BigInteger seed = _keccak256(seedStr.getBytes());
    // private static BigInteger prime = Config.FIELD_PRIME;
    private static int numRounds = 91;
    private static final BigInteger[] roundConstants;

    public MiMC7Hash(BigInteger... inputs) {
        BigInteger mimc7;
        if (inputs.length == 1) {
            mimc7 = new MiMC7Hash(inputs[0], inputs[0]).getOutput();
            output = mimc7;
        }
        else {
            output = inputs[0];
            for(int i=1; i<inputs.length; i++) {
                mimc7 = MiMC7Hash_enc(output, inputs[i]);
                output = mimc7;
            }
        }
    }

    public MiMC7Hash(BigInteger inputLeft, BigInteger inputRight) {
        this.inputLeft = inputLeft;
        this.inputRight = inputRight;
        buildCircuit();
    }

    private BigInteger MiMC7Hash_enc(BigInteger inputLeft, BigInteger inputRight) {
        this.inputLeft = inputLeft;
        this.inputRight = inputRight;
        BigInteger out = Encrypt(inputLeft, inputRight).add(inputLeft).add(inputRight).mod(GroupElement.FIELD_PRIME);
        return out;
    }

    static {
        roundConstants = new BigInteger[numRounds];
        roundConstants[0] = seed;
        for (int i = 1; i < numRounds; i++) {
            roundConstants[i] = _updateRoundConstant(roundConstants[i-1]);
        }
    }

    private void buildCircuit() {
        output = Encrypt(inputLeft, inputRight).add(inputLeft).add(inputRight).mod(GroupElement.FIELD_PRIME);
        // TODO: Extends to multiple inputs
    }

    private BigInteger MiMC_round(BigInteger message, BigInteger key, BigInteger rc) {
        BigInteger xored = message.add(key).add(rc).mod(GroupElement.FIELD_PRIME); // mod prime automatically
        
        BigInteger tmp = xored;
        for (int i=0; i<2; i++) {
            tmp = tmp.multiply(tmp).mod(GroupElement.FIELD_PRIME);
            xored = xored.multiply(tmp).mod(GroupElement.FIELD_PRIME);
        }
        return xored;
    }

    private BigInteger Encrypt(BigInteger message, BigInteger ek) {
        BigInteger result = message;
        BigInteger key = ek;
        // BigInteger roundConstant = seed;

        result = MiMC_round(result, key, BigInteger.ZERO);

        for (int i = 1; i < numRounds; i++) {
            // round_constant = _updateRoundConstant(round_constant);
            // roundConstant = roundConstants[i];
            result = MiMC_round(result, key, roundConstants[i]);
        }

        return result.add(key).mod(GroupElement.FIELD_PRIME);

    }

    private static BigInteger _keccak256(byte[] inputs) {
        byte[] out = keccak256.digest(inputs);

        String hex_string = byteArrayToHexString(out).toLowerCase();
        BigInteger res = new BigInteger(hex_string, 16);
        return res;
    }

    private static byte[] adjustBytes(byte[] input, int length) {
        if (input.length >= length) { // restrict byte length
            byte[] restrictedByte = new byte[length];
            System.arraycopy(input, input.length - length, restrictedByte, 0, length);
            return restrictedByte;
        }
        // zero padding
        byte[] res = new byte[32];
        byte[] pad = new byte[32 - input.length];

        Arrays.fill(pad, (byte) 0);

        System.arraycopy(pad, 0, res, 0, pad.length);
        System.arraycopy(input, 0, res, pad.length, input.length);

        return res;
    }

    private static BigInteger _updateRoundConstant(BigInteger rc) {
        byte[] byteArray = rc.toByteArray();
        byte[] padding_byte = adjustBytes(byteArray, 32);

        return _keccak256(padding_byte);
    }

    private static String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();

        for (byte b : bytes) {
            sb.append(String.format("%02X", b & 0xff));
        }

        return sb.toString();
    }

    public BigInteger getOutput() {
        return output;
    }

    public static void main(String[] args)
    {
        StringBuilder sb1 = new StringBuilder();
        StringBuilder sb2 = new StringBuilder();

        byte[] bt1 = new byte[32];
        byte[] bt2 = new byte[32];
        Random rnd = new Random(1);

        for(int i = 0; i<20; i++) {

            rnd.nextBytes(bt1);
            rnd.nextBytes(bt2);
            BigInteger b1 = new BigInteger(1, bt1);
            BigInteger b2 = new BigInteger(1, bt2);
            sb1.append(b1.toString(16)).append(' ').append(b2.toString(16)).append('\n');

            BigInteger hash = (new MiMC7Hash(b1, b2).getOutput());
            sb2.append(hash.toString(16)).append('\n');
        }
        System.out.println("MiMC7 in  "+ sb1.toString());
        System.out.println("MiMC7 out "+  sb2.toString());
    }
}