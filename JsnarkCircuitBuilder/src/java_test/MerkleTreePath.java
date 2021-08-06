package java_test;

import java.math.BigInteger;
import java_test.MiMC7Hash;
import java.util.Random;

public class MerkleTreePath {
    private final int treeHeight;
    private final BigInteger directionSelectorWire;
    private final BigInteger[] leafWires;
    private final BigInteger[] intermediateHashWires;
    private BigInteger outRoot;

    public MerkleTreePath(BigInteger directionSelectorWire, BigInteger[] leafWires, BigInteger[] intermediateHasheWires, int treeHeight) {
        this.directionSelectorWire = directionSelectorWire;
        this.treeHeight = treeHeight;
        this.leafWires = leafWires;
        this.intermediateHashWires = intermediateHasheWires;

        for (BigInteger hash : leafWires) {
            //System.out.println("Vote_Tree_in " + hash.toString(16));
        }

        buildCircuit();
    }

    private void buildCircuit() {
        BigInteger[] directionSelectorBits = getBitSplit(directionSelectorWire, (treeHeight));
        MiMC7Hash MiMC7 = new MiMC7Hash(leafWires);
        BigInteger currentHash = MiMC7.getOutput();

        // Apply CRH across tree path guided by the direction bits
        for (int i = 0; i < treeHeight; i++) {
            if(directionSelectorBits[i].toByteArray()[0] == 0)
                MiMC7 = new MiMC7Hash(intermediateHashWires[i], currentHash);
            else
                MiMC7 = new MiMC7Hash(currentHash, intermediateHashWires[i]);
            currentHash = MiMC7.getOutput();
        }
        outRoot = currentHash;
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

    public BigInteger getOutput() {
        return outRoot;
    }

    public String getOutputString() {
        return outRoot.toString(16);
    }

    public static void main(String[] args){
        BigInteger in1 = new BigInteger("1fca64aadf8c72571e0bb07a79cf3f1d97357470e5d7dd51a3bc15f38c7c6e22", 16);
        BigInteger in2 = new BigInteger("c6b29f54614c69fa95672d61dcacc7aa06d5236df49e25a8c7a1a8e0ba92db2", 16);
        BigInteger in3 = new BigInteger("242e5dac01ff9bc696a866fbe0cebeb2ef3b836de1f9344f3bd8da5ddcfd1899", 16);

        BigInteger[] tree_in = {in1, in2, in3};
        BigInteger[] intermediateHash = new BigInteger[16];
        BigInteger direction_selector = new BigInteger("73d5",16);
        //TODO: need to change directionselector

        Random rnd = new Random(5);
        byte[] rand_bytes = new byte[30];
        rnd.nextBytes(rand_bytes);

        for(int i =0; i<intermediateHash.length; i++) {
            rnd.nextBytes(rand_bytes);
            intermediateHash[i] = new BigInteger(1, rand_bytes);
            //intermediateHash[i] = new BigInteger("7fffffff", 16);
        }
        //TODO: need to change MerkleTree input(intermediateHasheWires)
        MerkleTreePath tree = new MerkleTreePath(direction_selector, tree_in, intermediateHash, 16);
        System.out.println("MiMC7 tree " + tree.getOutput().toString(16));   
    }
}