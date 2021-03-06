/*
 * run_ppzksnark.cpp
 *
 *      Author: Ahmed Kosba
 */

#include "CircuitReader.hpp"
#include <libsnark/gadgetlib2/integration.hpp>
#include <libsnark/gadgetlib2/adapters.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/voting/r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/voting/run_r1cs_gg_ppzksnark.hpp>
// #include <libsnark/zk_proof_systems/ppzksnark/voting/r1cs_gg_ppzksnark.hpp>

#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>

int main(int argc, char **argv) {
	for(int i = 0 ; i < argc ; i++)
	printf("%d : %s\n", i, argv[i]);
	libff::start_profiling();
	gadgetlib2::initPublicParamsFromDefaultPp();
	gadgetlib2::GadgetLibAdapter::resetVariableIndex();
	ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);
	
	int inputStartIndex = 0;
	if(argc == 5){
		if(strcmp(argv[1], "gg") != 0){
			cout << "Invalid Argument - Terminating.." << endl;
			return -1;
		} else{
			cout << "Using ppzsknark in the generic group model [Gro16]." << endl;
		}
		inputStartIndex = 1;	
	} 	

	

	// Read the circuit, evaluate, and translate constraints
	CircuitReader reader(argv[1 + inputStartIndex], argv[2 + inputStartIndex], pb);
	r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(
			*pb);
	const r1cs_variable_assignment<FieldT> full_assignment =
			get_variable_assignment_from_gadgetlib2(*pb);
	cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
	cs.auxiliary_input_size = full_assignment.size() - cs.num_inputs();

	// extract primary and auxiliary input
	const r1cs_primary_input<FieldT> primary_input(full_assignment.begin(),
			full_assignment.begin() + cs.num_inputs());
	const r1cs_auxiliary_input<FieldT> auxiliary_input(
			full_assignment.begin() + cs.num_inputs(), full_assignment.end());


	// only print the circuit output values if both flags MONTGOMERY and BINARY outputs are off (see CMakeLists file)
	// In the default case, these flags should be ON for faster performance.
	#if defined(MONTGOMERY_OUTPUT)
	cout <<"montgomery output on" << endl;
	#endif
	#if defined(BINARY_OUTPUT)
	cout << "output binary on " << endl;
	#endif

	char *name1;
	name1 = strtok(argv[1], ".");
	cout << argv[3] << endl;
	name1[strlen(name1)] = '\0';
	string name = name1;
	cout << name << endl;
	string filename;
    filename = "./datafiles/" + name + "_inouts.dat";
    std::ofstream inoutfile(filename);


	cout << endl << "Printing output assignment in readable format:: " << endl;
	std::vector<Wire> outputList = reader.getOutputWireIds();
	int start = reader.getNumInputs();
	int end = reader.getNumInputs() +reader.getNumOutputs();	
	cout << "numinputs" << start << endl << "numoutputs" << end-start << endl;

	std::vector<Wire> inputList = reader.getInputWireIds();
	int start2 = reader.getNumInputs();
	cout << start2 << endl;
	for(int i = 0 ; i < start2 ; i++){
		// string tmp 
		cout << "[INPUT]" << "value" << inputList[i] << "::";
		primary_input[i].print();

		inoutfile << primary_input[i] << OUTPUT_NEWLINE;
	}

	for (int i = start ; i < end; i++) {
		cout << "[output]" << " Value of Wire # " << outputList[i-reader.getNumInputs()] << " :: ";
		primary_input[i].print();
		inoutfile << primary_input[i] << OUTPUT_NEWLINE;
	}

    inoutfile.close();

	//assert(cs.is_valid());

	// removed cs.is_valid() check due to a suspected (off by 1) issue in a newly added check in their method.
        // A follow-up will be added.
	
	r1cs_example<FieldT> example(cs, primary_input, auxiliary_input);
	const bool test_serialization = false;
	bool successBit = false;
	//string name = argv[2];
	
	if(strcmp(argv[3], "setup") == 0)
	{
		if(!cs.is_satisfied(primary_input, auxiliary_input)){
		cout << "The constraint system is  not satisifed by the value assignment - Terminating." << endl;
		return -1;
		}
		libsnark::run_r1cs_gg_ppzksnark_setup<libsnark::default_r1cs_gg_ppzksnark_pp>(example, test_serialization, name);

		return 0;
	}
	else if (strcmp(argv[3], "verify") == 0)
	{
		// FILE *fp = fopen(filename);
		// unsigned char *arr = (char *)malloc(sizeof(char) * size);
		// fread(arr, sizeof(unsigned char), size, in);
		// for(int i = 0 ; i < size ; i++){
			
		// }
		// for (int i = 0; i < end; i++)
		// {

		// }
		if(argc == 4) {
		
		successBit = libsnark::run_r1cs_gg_ppzksnark_verify<libff::default_ec_pp>(example, test_serialization, name);

		} else {
			// The following code makes use of the observation that 
			// libsnark::default_r1cs_gg_ppzksnark_pp is the same as libff::default_ec_pp (see r1cs_gg_ppzksnark_pp.hpp)
			// otherwise, the following code won't work properly, as GadgetLib2 is hardcoded to use libff::default_ec_pp.
			successBit = libsnark::run_r1cs_gg_ppzksnark_verify<libsnark::default_r1cs_gg_ppzksnark_pp>(
				example, test_serialization, name);
		}

		if(!successBit){
			cout << "Problem occurred while running the ppzksnark algorithms .. " << endl;
			return 0;
		}	
		return 0;
	}
	else if (strcmp(argv[3], "run") == 0)
	{
		if(!cs.is_satisfied(primary_input, auxiliary_input)){
		cout << "The constraint system is  not satisifed by the value assignment - Terminating." << endl;
		return -1;
		}
		if(argc == 4) {
			
			libsnark::run_r1cs_gg_ppzksnark<libff::default_ec_pp>(example, test_serialization, name);

		} else {
			// The following code makes use of the observation that 
			// libsnark::default_r1cs_gg_ppzksnark_pp is the same as libff::default_ec_pp (see r1cs_gg_ppzksnark_pp.hpp)
			// otherwise, the following code won't work properly, as GadgetLib2 is hardcoded to use libff::default_ec_pp.
			libsnark::run_r1cs_gg_ppzksnark<libsnark::default_r1cs_gg_ppzksnark_pp>(
				example, test_serialization, name);
		}

		return 0;
	}
	
	else if(strcmp(argv[3], "all") == 0)
	{
		libsnark::run_r1cs_gg_ppzksnark_setup<libsnark::default_r1cs_gg_ppzksnark_pp>(example, test_serialization, name);
		
		if(argc == 4) {
			
			libsnark::run_r1cs_gg_ppzksnark<libff::default_ec_pp>(example, test_serialization, name);
			successBit = libsnark::run_r1cs_gg_ppzksnark_verify<libff::default_ec_pp>(example, test_serialization, name);
			libsnark::get_parameters<libff::default_ec_pp>(name);

		} else {
			// The following code makes use of the observation that 
			// libsnark::default_r1cs_gg_ppzksnark_pp is the same as libff::default_ec_pp (see r1cs_gg_ppzksnark_pp.hpp)
			// otherwise, the following code won't work properly, as GadgetLib2 is hardcoded to use libff::default_ec_pp.
			libsnark::run_r1cs_gg_ppzksnark<libsnark::default_r1cs_gg_ppzksnark_pp>(
				example, test_serialization, name);
			successBit = libsnark::run_r1cs_gg_ppzksnark_verify<libsnark::default_r1cs_gg_ppzksnark_pp>(
				example, test_serialization, name);
			libsnark::get_parameters<libsnark::default_r1cs_gg_ppzksnark_pp>(name);

		}

		if(!successBit){
			cout << "Problem occurred while running the ppzksnark algorithms .. " << endl;
			return 0;
		}
		
	}

	else if(strcmp(argv[3], "param") == 0){
		if ( argc == 4){
		libsnark::get_parameters<libff::default_ec_pp>(name);
		}
		else{
			libsnark::get_parameters<libsnark::default_r1cs_gg_ppzksnark_pp>(name);
		}
	}
	return 0;
}

