/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package examples.gadgets.hash;

import circuit.operations.Gadget;
import circuit.structure.Wire;

/**
 * A Merkle tree authentication gadget using the subsetsum hash function
 * 
 */

public class MerkleTreePathGadget_MiMC7 extends Gadget {

	//private static int digestWidth = SubsetSumHashGadget.DIMENSION; // 3

	private int treeHeight;
	private Wire directionSelectorWire;
	private Wire[] directionSelectorBits;
	private Wire[] leafWires;
	private Wire[] intermediateHashWires;
	private Wire[] outRoot;

	public MerkleTreePathGadget_MiMC7(Wire directionSelectorWire, Wire[] leafWires, Wire[] intermediateHasheWires,
			 int treeHeight, String... desc) {

		super(desc);
		this.directionSelectorWire = directionSelectorWire;
		this.treeHeight = treeHeight;
		this.leafWires = leafWires;
		this.intermediateHashWires = intermediateHasheWires;

		buildCircuit();
	}

	private void buildCircuit() {
		//directionSelectorBits = new viewWireGadget(new Wire[] {directionSelectorWire}, treeHeight).getOutputWires();
		directionSelectorBits = directionSelectorWire.getBitWires(treeHeight).asArray();

		// Apply CRH to leaf data
		MiMC7Gadget MiMC7 = new MiMC7Gadget(leafWires);
        Wire currentHash = MiMC7.getOutputWires()[0];

		// Apply CRH across tree path guided by the direction bits
		Wire temp, temp2;
		Wire[] inHash = new Wire[2];
		for (int i = 0; i < treeHeight; i++) {
            temp = currentHash.sub(intermediateHashWires[i]);
            temp2 = directionSelectorBits[i].mul(temp);
            inHash[0] = intermediateHashWires[i].add(temp2);
            temp = currentHash.add(intermediateHashWires[i]);
            inHash[1] = temp.sub(inHash[0]);

			// in0 = (c-inter)*d + inter
			// in1 = (c+inter) - in0			
			// d:0 > inter / c
			// d:1 > c / inter            
            MiMC7 = new MiMC7Gadget(inHash);
            currentHash = MiMC7.getOutputWires()[0];
		}
		outRoot = new Wire[] {currentHash};
	}

	@Override
	public Wire[] getOutputWires() {
		return outRoot;
	}

}
