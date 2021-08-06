/*******************************************************************************
 * Author: Seongho Park <shparkk95@kookmin.ac.kr>
 *******************************************************************************/
package examples.generators;

import java.math.BigInteger;
// import java.math.*;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.diffieHellmanKeyExchange.ECGroupGeneratorGadget;
import examples.gadgets.diffieHellmanKeyExchange.ECGroupOperationGadget;

import java_test.GroupElement;
import java_test.Curve25519;
import java.security.SecureRandom;

public class Tally extends CircuitGenerator {
    /* INPUT */
    private Wire Gx, Gy;
    private Wire Ux, Uy;
    private Wire Vsum_x, Vsum_y;
    private Wire Wsum_x, Wsum_y;
    private Wire msgsum; //MAX = (15) * 2 ^ 16
    /* WITNESS */
    private Wire SK;

    private int numofelector;
    public static final int EXPONENT_BITWIDTH = 254; // in bits


    public Tally(String circuitName, int numofelector) {
        super(circuitName);
        this.numofelector = numofelector;
    }

    public Wire[] expwire(Wire input){
        Wire[] output = input.getBitWires(EXPONENT_BITWIDTH).asArray();
		return output;
    }
    
    @Override
    protected void buildCircuit(){
        Gx = createInputWire("Gx");         Gy = createInputWire("Gy");
        Ux = createInputWire("Ux");         Uy = createInputWire("Uy");
        Vsum_x = createInputWire("Vsum_x"); Vsum_y = createInputWire("Vsum_y"); /*vsum*/
        Wsum_x = createInputWire("Wsum_x"); Wsum_y = createInputWire("Wsum_y"); /*wsum*/
        msgsum = createInputWire("msgsum");

        SK = createProverWitnessWire("sk");

        ECGroupGeneratorGadget dec1 = new ECGroupGeneratorGadget(Gx, Gy, SK);
        ECGroupOperationGadget dec2 = new ECGroupOperationGadget(Vsum_x, Vsum_y, SK, Gx, Gy, msgsum);

        Wire[] check1 = dec1.getOutputWires();
        Wire[] check2 = dec2.getOutputWires();

        addEqualityAssertion(check1[0], Ux, "check1");
        addEqualityAssertion(check1[1], Uy, "check1");
        addEqualityAssertion(check2[0], Wsum_x, "check2");
        addEqualityAssertion(check2[1], Wsum_y, "check2");
    }

	SecureRandom GlobalRand = new SecureRandom();
	public BigInteger setRandombit(BigInteger maxValue){
		byte[] rand_bytes = new byte[(maxValue.bitLength()/8)+1];
		BigInteger out;
		do{
			GlobalRand.nextBytes(rand_bytes);
			out = new BigInteger(1,rand_bytes);
		}while(out.bitLength() != maxValue.bitLength() || out.compareTo(maxValue) == 1);
		return out;
	}

    @Override
    public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
        int idx;
		BigInteger Big_msg, Big_msg_sum, rand;
        Curve25519 EC_G, EC_U;
        Curve25519 EC_S, EC_T;
        Curve25519 EC_V, EC_W;

        EC_G = new Curve25519(GroupElement.G, false);
        EC_U = new Curve25519(GroupElement.U, false);
        Big_msg_sum = BigInteger.ZERO;

        Curve25519 EC_Vsum = null, EC_Wsum = null;
        System.out.println("Generate " + this.numofelector + " people test cases.");

        // This for loop creates a voter's message assuming the counting situation.
        for(int i = 1; i <= this.numofelector; i++)     
        {
            idx = (GlobalRand.nextInt(15));							    //idx : Android seccret value
            Big_msg = (new BigInteger("0")).setBit(16*idx);				// Big_msg : Android seccret value 

            EC_S = EC_G.mul(setRandombit(GroupElement.SUBGROUP_ORDER)); // Generate for loop
            EC_T = EC_S.mul(GroupElement.rho).add(EC_G);				

            rand = setRandombit(GroupElement.SUBGROUP_ORDER);			// rand : Android seccret value 
            EC_V = (EC_G.mul(rand)).add(EC_S.mul(Big_msg));             // EC_V : Android public voting value 
            EC_W = (EC_U.mul(rand)).add(EC_T.mul(Big_msg));             // EC_W : Android public voting value

            EC_Vsum = EC_Vsum == null ? EC_V : EC_Vsum.add(EC_V);
            EC_Wsum = EC_Wsum == null ? EC_W : EC_Wsum.add(EC_W);
            Big_msg_sum = Big_msg_sum.add(Big_msg);                     
            if(i%100 == 0)
                System.out.println(i+" people generated");
        }
        byte[] arrBytes = Big_msg_sum.toByteArray();
        for(byte b : arrBytes)
            System.out.println(Integer.toHexString(b));

        System.out.println("Msg Sum:: " + Big_msg_sum.toString(16));
        System.out.println("EC_Vsum:: " + EC_Vsum.getPoint().toString(16));
        System.out.println("EC_Wsum:: " + EC_Wsum.getPoint().toString(16));

        circuitEvaluator.setWireValue(Gx, EC_G.getPoint().x);
        circuitEvaluator.setWireValue(Gy, EC_G.getPoint().y);
        circuitEvaluator.setWireValue(Ux, EC_U.getPoint().x);
        circuitEvaluator.setWireValue(Uy, EC_U.getPoint().y);
        circuitEvaluator.setWireValue(Vsum_x, EC_Vsum.getPoint().x);
        circuitEvaluator.setWireValue(Vsum_y, EC_Vsum.getPoint().y);
        circuitEvaluator.setWireValue(Wsum_x, EC_Wsum.getPoint().x);
        circuitEvaluator.setWireValue(Wsum_y, EC_Wsum.getPoint().y);

        circuitEvaluator.setWireValue(msgsum, Big_msg_sum);
        circuitEvaluator.setWireValue(SK, GroupElement.rho);
    }

    public static void main(String[] args) throws Exception{
        int number_of_voter;
        if(args.length == 0 || args.length > 1)
            number_of_voter = 1000;
        else
            number_of_voter = Integer.parseInt(args[0].trim());

        Tally tally = new Tally("tally", number_of_voter);
        tally.generateCircuit();
        tally.evalCircuit();
        tally.prepFiles();
        tally.runLibsnark();
    }
}
