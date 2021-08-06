/*******************************************************************************
 * Author: Seongho Park <shparkk95@kookmin.ac.kr>
 *******************************************************************************/
package examples.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.hash.MiMC7Gadget;
import java_test.MiMC7Hash;

public class Register extends CircuitGenerator {

    /*  input */
    private Wire HashOut;
    /* witness */
    private Wire SK_id;

    /******************* BigInteger Values  ******************/
    public BigInteger sk_id;
    private MiMC7Gadget MiMC7;
    public Register(String circuitName){
        super(circuitName);
    }

    @Override
    protected void buildCircuit(){
        HashOut = createInputWire("hashin");
		SK_id = createProverWitnessWire("sk_id"); // voter private key

        MiMC7 = new MiMC7Gadget(new Wire[] {SK_id});
		Wire PK_id = MiMC7.getOutputWires()[0];

        addEqualityAssertion(PK_id, HashOut);
    }

    @Override
    public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
        SecureRandom random = new SecureRandom();
        byte[] random_bytes = new byte[30];

        random.nextBytes(random_bytes);
        BigInteger testcase_sk = new BigInteger(1, random_bytes);
        BigInteger testcase_hash = new MiMC7Hash(testcase_sk).getOutput();

        circuitEvaluator.setWireValue(SK_id, testcase_sk);
        circuitEvaluator.setWireValue(HashOut, testcase_hash);
    }

    public static void main(String[] arga) throws Exception{
        Register register = new Register("Register");
        register.generateCircuit();
        register.evalCircuit();
        register.prepFiles();
        register.runLibsnarksetup();
        register.runLibsnarkproof();
    }
}
