/** @file
 *****************************************************************************
 Test program that exercises the Dario (first generator, then
 prover, then verifier) on a synthetic R1CS instance.

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

template<typename ppT>
void test_dario(size_t num_constraints,
                size_t input_size)
{
    libff::print_header("(enter) Test Dario");

    bool test_serialization = true;
    r1cs_example<libff::Fr<ppT> > example = generate_r1cs_example_with_binary_input<libff::Fr<ppT> >(num_constraints, input_size);
    bool bit = run_dario<ppT>(example, test_serialization);
    assert(bit);

    libff::print_header("(leave) Test Dario");
}

int main()
{
    default_dario_pp::init_public_params();
    libff::start_profiling();

    test_dario<default_dario_pp>(1000, 100);
}
