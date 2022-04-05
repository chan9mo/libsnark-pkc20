/** @file
 *****************************************************************************

 Declaration of functionality that runs the R1CS GG-ppzkSNARK for
 a given R1CS example.

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef RUN_DARIO_HPP_
#define RUN_DARIO_HPP_

#include <libff/algebra/curves/public_params.hpp>

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>

namespace libsnark {

/**
 * Runs the RQ-SNARK (generator, prover, and verifier) for a given
 * R1CS example (specified by a constraint system, input, and witness).
 */

template<typename ppT>
bool run_dario(const r1cs_example<libff::Fr<ppT>> &example,
               const bool test_serialization);

} // libsnark

#include <libsnark/zk_proof_systems/dario/run_dario.tcc>

#endif // RUN_DARIO_HPP_
