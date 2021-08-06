/*******************************************************************************
 * Author: Jaekyoung Choi <cjk2889@kookmin.ac.kr>
 *******************************************************************************/
package examples.generators;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.acl.Group;
import java.util.Random;
import java.util.function.BiFunction;

import util.Util;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.diffieHellmanKeyExchange.ECGroupOperationGadget;
import examples.gadgets.hash.MerkleTreePathGadget_MiMC7;
import examples.gadgets.hash.MiMC7Gadget;

import java_test.*;

public class Vote extends CircuitGenerator {
	/********************* INPUT ***************************/
	private Wire Gx, Gy;
	private Wire Ux, Uy;
	private Wire Vx_in, Wx_in;
	private Wire Vy_in, Wy_in;
	private Wire E_id;
	private Wire root_in;
	private Wire sn_in, pk_in;
	private Wire root_out;
	
	/********************* Witness ***************************/
	private Wire Sx, Sy;
	private Wire Tx, Ty;
	private Wire sk_id;
	private Wire randomizedEnc;
	private Wire msg; 

	/********************* MerkleTree ***************************/
	private Wire directionSelector;
	private Wire[] intermediateHashWires;
	private int treeHeight;
	private int numofelector, msgsize;

	public static final int EXPONENT_BITWIDTH = 254; // in bits
	public Vote(String circuitName, int treeHeight, int numofelector) {
		super(circuitName);
		this.treeHeight = treeHeight;
		this.numofelector = numofelector;
		this.msgsize = (int)( Math.log(numofelector) / Math.log(2) );
	}

	@Override
	protected void buildCircuit() {	
		Gx = createInputWire("Gx");	Gy = createInputWire("Gy");
		Ux = createInputWire("Ux");	Uy = createInputWire("Uy");
		Vx_in = createInputWire("Vx_in");	Vy_in = createInputWire("Vy_in");
		Wx_in = createInputWire("Wx_in");	Wy_in = createInputWire("Wy_in");
		E_id = createInputWire("e");
		pk_in = createInputWire("pk_in");
		sn_in = createInputWire("sn_in");
		root_in = createInputWire("root_in");
		////////////////////////////////////////////////////////////////////////////////////

		sk_id = createProverWitnessWire("sk_id");
		Sx = createProverWitnessWire("Sx");Sy = createProverWitnessWire("Sy");
		Tx = createProverWitnessWire("Tx");Ty = createProverWitnessWire("Ty");
		randomizedEnc = createProverWitnessWire("rand");
		msg = createProverWitnessWire("msg");

		directionSelector = createProverWitnessWire("Direction selector");
		intermediateHashWires = createProverWitnessWireArray(treeHeight, "Intermediate Hashes");

		MiMC7Gadget sn_hash = new MiMC7Gadget(new Wire[] {Sx, Tx, sk_id, E_id});
		Wire sn_out = sn_hash.getOutputWires()[0];

		ECGroupOperationGadget encV = new ECGroupOperationGadget(Gx, Gy, randomizedEnc, Sx, Sy, msg); //하나에 120ms 정도
		ECGroupOperationGadget encW = new ECGroupOperationGadget(Ux, Uy, randomizedEnc, Tx, Ty, msg);

		MiMC7Gadget pk_hash = new MiMC7Gadget(new Wire[] {sk_id});
		Wire pk_out = pk_hash.getOutputWires()[0];
		
		Wire[] V_out = encV.getOutputWires();
		Wire[] W_out = encW.getOutputWires();
		Wire[] ekpk = {Sx, Tx, pk_out};
		MerkleTreePathGadget_MiMC7 merkleTreeGadget = new MerkleTreePathGadget_MiMC7(directionSelector, ekpk, intermediateHashWires, treeHeight);
		root_out = merkleTreeGadget.getOutputWires()[0];
		//makeOutputArray(root, "Root");

		addEqualityAssertion(pk_out, pk_in);
		addEqualityAssertion(sn_out, sn_in);
		addEqualityAssertion(V_out[0], Vx_in);
		addEqualityAssertion(V_out[1], Vy_in);
		addEqualityAssertion(W_out[0], Wx_in);
		addEqualityAssertion(W_out[1], Wy_in);
		addEqualityAssertion(root_out, root_in);
	}

	public void print_bigint(BigInteger... ins){
		for(BigInteger b : ins){
			System.out.println(b.toString(10));
			if(b.compareTo(GroupElement.FIELD_PRIME) == 1)
				System.out.println("Invalid input... so sad...");
		}	
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
		Curve25519 EC_S, EC_T, EC_G;	  // Server Curve
		Curve25519 EC_V, EC_W, EC_U;	  // Android Curve
		BigInteger Big_Eid;				  // Android public value
		MiMC7Hash sn_mimc, pk_mimc;		  // Android public value
		BigInteger rand, Big_msg, Big_sk; // Android secret random value

		BigInteger direction;			  // Block Chain public value
		BigInteger[] intermediateHash = new BigInteger[treeHeight]; // Block Chain public value
		EC_G = new Curve25519(GroupElement.G, false);
		EC_U = new Curve25519(GroupElement.U, false);

		//////////////////////////////////  Server Part  //////////////////////////////////
		EC_S = EC_G.mul(setRandombit(GroupElement.SUBGROUP_ORDER)); // setRandombit(GroupElement.SUBGROUP_ORDER) : server seccret key 
		EC_T = EC_S.mul(GroupElement.rho).add(EC_G);				// GroupElement.rho : server seccret value 	

		//////////////////////////////////  Android Part  //////////////////////////////////
		int idx = (GlobalRand.nextInt(15));							//     idx : Android seccret value
		Big_Eid = new BigInteger(Integer.toHexString(idx),16);		// Big_Eid : Android public value
		Big_msg = (new BigInteger("0")).setBit(16*idx);				// Big_msg : Android seccret value 
		rand = setRandombit(GroupElement.SUBGROUP_ORDER);			//    rand : Android seccret value 
		EC_V = (EC_G.mul(rand)).add(EC_S.mul(Big_msg));
		EC_W = (EC_U.mul(rand)).add(EC_T.mul(Big_msg));

		int i_sk = (GlobalRand.nextInt(1000000));
		Big_sk = new BigInteger(Integer.toHexString(i_sk),16);
		sn_mimc = new MiMC7Hash(EC_S.getPoint().x, EC_T.getPoint().x, Big_sk, Big_Eid); 		//{Sx, Tx, sk_id, E_id}
		pk_mimc = new MiMC7Hash(Big_sk);

		direction = setRandombit(new BigInteger(Integer.toHexString(1<<(treeHeight-1)),16));	// bitLength of this variable  must be (2^(treeHeight) - 1)bits
		for(int i = 0; i < treeHeight; i++ ) 
			intermediateHash[i] = setRandombit(GroupElement.FIELD_PRIME);
		BigInteger[] tree_input = {EC_S.getPoint().x, EC_T.getPoint().x, pk_mimc.getOutput() };
		MerkleTreePath merklepath = new MerkleTreePath(direction, tree_input, intermediateHash, treeHeight);

		//////////////////////////////////  Android Part  //////////////////////////////////
		circuitEvaluator.setWireValue(Gx, EC_G.getPoint().x);
		circuitEvaluator.setWireValue(Gy, EC_G.getPoint().y);
		circuitEvaluator.setWireValue(Ux, EC_U.getPoint().x);
		circuitEvaluator.setWireValue(Uy, EC_U.getPoint().y);
		circuitEvaluator.setWireValue(Vx_in, EC_V.getPoint().x);
		circuitEvaluator.setWireValue(Vy_in, EC_V.getPoint().y);
		circuitEvaluator.setWireValue(Wx_in, EC_W.getPoint().x);
		circuitEvaluator.setWireValue(Wy_in, EC_W.getPoint().y);
		circuitEvaluator.setWireValue(E_id, Big_Eid);
		circuitEvaluator.setWireValue(pk_in, pk_mimc.getOutput());
		circuitEvaluator.setWireValue(sn_in, sn_mimc.getOutput());
		circuitEvaluator.setWireValue(root_in, merklepath.getOutput());
		circuitEvaluator.setWireValue(sk_id, Big_sk);
		circuitEvaluator.setWireValue(Sx, EC_S.getPoint().x);
		circuitEvaluator.setWireValue(Sy, EC_S.getPoint().y);
		circuitEvaluator.setWireValue(Tx, EC_T.getPoint().x);
		circuitEvaluator.setWireValue(Ty, EC_T.getPoint().y);
		circuitEvaluator.setWireValue(randomizedEnc, rand);
		circuitEvaluator.setWireValue(msg, Big_msg);
		circuitEvaluator.setWireValue(directionSelector, direction);		
		for (int i = 0; i < treeHeight; i++) { 
			circuitEvaluator.setWireValue(intermediateHashWires[i], intermediateHash[i]);
		}
	}

	public static void main(String[] args) throws Exception {
		Vote generator = new Vote("Vote", 16, 15); // 16 : 5 10 15
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}
}
