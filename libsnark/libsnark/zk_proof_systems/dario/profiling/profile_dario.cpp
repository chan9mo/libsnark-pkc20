/** @file
 *****************************************************************************
 Profiling program that exercises the Dario (first generator, then prover,
 then verifier) on a synthetic R1CS instance.

 The command

     $ libsnark/zk_proof_systems/dario/profiling/profile_dario 1000 10 Fr

 exercises Dario (first generator, then prover, then verifier) on an R1CS instance with 1000 equations and an input consisting of 10 field elements.

 (If you get the error `zmInit ERR:can't protect`, see the discussion [above](#elliptic-curve-choices).)

 The command

     $ libsnark/zk_proof_systems/dario/profiling/profile_dario 1000 10 bytes

 does the same but now the input consists of 10 bytes.

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/
#include <cassert>
#include <cstdio>

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#include <libsnark/common/default_types/dario_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/dario/run_dario.hpp>

using namespace libsnark;

int main(int argc, const char * argv[])
{
    default_dario_pp::init_public_params();
    libff::start_profiling();

    if (argc == 2 && strcmp(argv[1], "-v") == 0)
    {
        libff::print_compilation_info();
        return 0;
    }

    if (argc != 3 && argc != 4)
    {
        printf("usage: %s num_constraints input_size [Fr|bytes]\n", argv[0]);
        return 1;
    }
    const int num_constraints = atoi(argv[1]);
    int input_size = atoi(argv[2]);
    if (argc == 4)
    {
        assert(strcmp(argv[3], "Fr") == 0 || strcmp(argv[3], "bytes") == 0);
        if (strcmp(argv[3], "bytes") == 0)
        {
            input_size = libff::div_ceil(8 * input_size, libff::Fr<libff::default_ec_pp>::capacity());
        }
    }

    libff::enter_block("Generate Dario example");
    r1cs_example<libff::Fr<default_dario_pp> > example = generate_r1cs_example_with_field_input<libff::Fr<default_dario_pp> >(num_constraints, input_size);
    libff::leave_block("Generate Dario example");

    libff::print_header("(enter) Profile Dario");
    bool test_serialization = true;

    run_dario<default_dario_pp>(example, test_serialization);
    //run_dario<default_dario_pp>(r1cs_example<Fp_model<4, ((const bigint<4>&)(& bn128_modulus_r))> >&, const bool&)
    libff::print_header("(leave) Profile Dario");
}