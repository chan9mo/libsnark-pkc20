/** @file
*****************************************************************************

Declaration of interfaces for a Polyomial Evaluation SNARK in QPP Model.

This includes:
- class for CRS
- class for statement
- class for dario_witness
- class for dario_proof
- class for polynomial: BPC_poly 사용
- generator algorithm: BPC.Generator, Lego.Generator를 쓰면 된다.
- prover algorithm
- verifier algorihtm
- online verifier algorithm (나중에 구현: Without Hiding Property of P,Q)

References:

\[PKC20]:
 "Boosting Verifiable Computation on Encrypted Data",
 Dario Fiore,
 IACR-PKC-2020,
 <https://eprint.iacr.org/2020/132>


*****************************************************************************
* @author     This file is part of vCNN, developed by SnP Lab, Hanyang University
* @copyright  MIT license (see LICENSE file) (?)
*****************************************************************************/

#ifndef HPP_
#define HPP_

#include <memory>
#include <libff/algebra/curves/public_params.hpp>
#include <libsnark/common/data_structures/accumulation_vector.hpp>
#include <libsnark/knowledge_commitment/knowledge_commitment.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark_params.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/dario/components/polycommit/bpc.hpp>
#include <libsnark/zk_proof_systems/dario/components/evalproof/bpe.hpp>
#include <libsnark/zk_proof_systems/dario/components/lego/lego_cp_snark.hpp>
#include <libsnark/zk_proof_systems/dario/components/lego/lego_ss.hpp>
#include <libsnark/zk_proof_systems/dario/dario_params.hpp>

namespace libsnark {

/******************************** CRS ********************************/
template <typename ppT>
class dario_crs
{
    public:
    bpc_key<ppT> crs_bpc = bpc_key<ppT>();
    lego_cp_snark_keypair<ppT> crs_lego = lego_cp_snark_keypair<ppT>();

    dario_crs(
        bpc_key<ppT> crs_bpc,
        lego_cp_snark_keypair<ppT> crs_lego) :

            crs_bpc(std::move(crs_bpc)),
            crs_lego(std::move(crs_lego)) {};
};

/******************************** dario_statement ********************************/
template <typename ppT>
class dario_statement
{
    public:
    bpc_commit<ppT> commit = bpc_commit<ppT>();
    bpc_poly<ppT> pubpoly = bpc_poly<ppT>();

    dario_statement(
        bpc_commit<ppT> commit,
        bpc_poly<ppT> pubpoly) :

            commit(std::move(commit)),
            pubpoly(std::move(pubpoly)) {};
};

/******************************** dario_witness ********************************/
template <typename ppT>
class dario_witness
{
    public:
    libff::G1_vector<bpc_unipoly<ppT>> n_polys = libff::G1_vector<bpc_unipoly<ppT>>();
    bpc_poly<ppT> Tpoly = bpc_poly<ppT>();

    dario_witness(
        libff::G1_vector<bpc_unipoly<ppT>> n_polys,
        bpc_poly<ppT> Tpoly) :

            n_polys(std::move(n_polys)),
            Tpoly(std::move(Tpoly)) {};
};

/******************************** dario_proof ********************************/
template <typename ppT>
class dario_proof
{
    public:
    bpc_commit<ppT> commit_t = bpc_commit<ppT>();
    bpc_commit<ppT> commit_prime = bpc_commit<ppT>();
    lego_cp_snark_proof<ppT> proof_lego = lego_cp_snark_proof<ppT>();
    bpe_proof<ppT> proof_mue = bpe_proof<ppT>();

    dario_proof(
        bpc_commit<ppT> commit_t,
        bpc_commit<ppT> commit_prime,
        lego_cp_snark_proof<ppT> proof_lego,
        bpe_proof<ppT> proof_mue) :

            commit_t(std::move(commit_t)),
            commit_prime(std::move(commit_prime)),
            proof_lego(std::move(proof_lego)),
            proof_mue(std::move(proof_mue)) {};
};

/******************************** Main Algorithms ********************************/

/**
 * Generator: Outputs crs
 */
template<typename ppT>
dario_crs<ppT> crs_generator(int &dimension,
                       int &length,
                       r1cs_gg_ppzksnark_constraint_system<ppT> &r1cs,
                       r1cs_gg_ppzksnark_primary_input<ppT> &primary_input,
                       relation<ppT> &R_link);  

/**
 * Prover: Outputs dario_proof
 */

template<typename ppT>
dario_proof<ppT> prover(dario_crs<ppT> &crs,
                        dario_statement<ppT> &st,
                        dario_witness<ppT> &wit,
                        dario_primary_input<ppT> &primary_input);          

/**
 * Verifier: Verifies dario_proof
 */
template <typename ppT>
bool verifier(dario_crs<ppT> &crs,
              dario_statement<ppT> &st,
              dario_proof<ppT> &dario_proof);
}

#include <libsnark/zk_proof_systems/dario/dario.tcc>

#endif