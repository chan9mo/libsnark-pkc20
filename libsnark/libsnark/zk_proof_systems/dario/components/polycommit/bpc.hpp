/** @file
*****************************************************************************

Declaration of interfaces for a polynomial commitment in QPP Model.

This includes:
- class for commitment key
- class for commitment
- class for polynomial
- generator algorithm
- commitment algorithm
- commitment vefiry algorihtm
- open verifier algorithm

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

#ifndef BPC_HPP_
#define BPC_HPP_

#include <memory>

#include <libff/algebra/curves/public_params.hpp>
#include <libsnark/common/data_structures/accumulation_vector.hpp>
#include <libsnark/knowledge_commitment/knowledge_commitment.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark_params.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

namespace libsnark
{

/******************************** Commitment key ********************************/

    template <typename ppT>
    class bpc_key
    {
    public:
        //dimension, length
        int dimension;
        int length;
        //libff::G1<ppT> g1;
        libff::G2<ppT> g2;
        libff::G1<ppT> h;
        //libff::G1<ppT> g1_hat;
        libff::G2<ppT> g2_hat;
        libff::G1<ppT> h_hat;

        /*libff::G1<ppT> alpha_g1;
        libff::G1<ppT> beta_g1;
        libff::G1<ppT> gamma_g1;
        libff::G2<ppT> alpha_g2;
        libff::G2<ppT> beta_g2;
        libff::G2<ppT> gamma_g2;*/

        libff::G1_vector<libff::G1_vector<ppT>> g1_ij;
        libff::G1_vector<libff::G1_vector<ppT>> g1_hat_ij;

        bpc_key(
            int dimension,
            int length,
            //libff::G1<ppT> &&g1,
            libff::G2<ppT> &&g2,
            libff::G1<ppT> &&h,
            //libff::G1<ppT> &&g1_hat,
            libff::G2<ppT> &&g2_hat,
            libff::G1<ppT> &&h_hat,
            /*libff::G1<ppT> &&alpha_g1,
            libff::G2<ppT> &&alpha_g2,
            libff::G1<ppT> &&beta_g1,
            libff::G2<ppT> &&beta_g2,
            libff::G1<ppT> &&gamma_g1,
            libff::G2<ppT> &&gamma_g2,*/
            libff::G1_vector<ppT> &&g1_ij,
            libff::G1_vector<ppT> &&g1_hat_ij) :
            
            //g1(std::move(g1)),
            dimension(std::move(dimension)),
            length(std::move(length)),
            g2(std::move(g2)),
            h(std::move(h)),
            //g1_hat(std::move(g1_hat)),
            g2_hat(std::move(g2_hat)),
            h_hat(std::move(h_hat)),
            /*alpha_g1(std::move(alpha_g1)),
            alpha_g2(std::move(alpha_g2)),
            beta_g1(std::move(beta_g1)),
            beta_g2(std::move(beta_g2)),
            gamma_g1(std::move(gamma_g1)),
            gamma_g2(std::move(gamma_g2)),*/
            g1_ij(std::move(g1_ij)),
            g1_hat_ij(std::move(g1_hat_ij)) {};        
};

/******************************** Commitment ********************************/

template <typename ppT>
class bpc_commit
{
    public:
    libff::G1<ppT> commit;
    libff::G1<ppT> commit_hat;
    libff::Fr<ppT> rho;

    bpc_commit(
        libff::G1<ppT> commit,
        libff::G1<ppT> commit_hat,
        libff::Fr<ppT> rho) : 

            commit(std::move(commit)),
            commit_hat(std::move(commit_hat),
            rho(std::move(rho))) {};
};

/******************************** Polynomial ********************************/
template <typename ppT>
class bpc_unipoly
{
    public:
    libff::G1_vector<ppT> coef;
    libff::Fr<ppT> count;

    bpc_unipoly(
        libff::G1_vector<ppT> coef,
        int count) :

        coef(std::move(coef)),
        count(std::move(count))
        {};
};


template <typename ppT>
class bpc_poly
{
    public:
    libff::G1_vector<libff::G1_vector<ppT>> coef;

    bpc_poly(
        libff::G1_vector<libff::G1_vector<ppT>> coef) :
        coef(std::move(coef))
        {};
};
//vector를 원소로 가지는 vector

/***************************** Main algorithms ******************************/


/**
 * Generator: Generates Commitment keys  
 */

template <typename ppT>
bpc_key<ppT> bpc_generator(int &dimension, 
                           int &length);

/**
 * MPC to BPC : Outputs Poly 
 */

template <typename ppT>
bpc_poly<ppT> mpc_to_bpc(bpc_unipoly<ppT> &polynomial);

/**
 * Commit: Outputs Commit, rho
 */

template <typename ppT>
bpc_commit<ppT> bpc_commitment(bpc_key<ppT> &ck, 
                           bpc_poly<ppT> &polynomial);

/**
 * CommitVer: Verifies Commiement
 */
template <typename ppT>
bool bpc_commit_verifier(bpc_key<ppT> &ck, 
                         bpc_commit<ppT> &commit);

/**
 * OpenVer: Opens Commiement & Verifies Opened Value
 */

template <typename ppT>
bool bpc_open_verifier(bpc_key<ppT> &ck, 
                       bpc_commit<ppT> &commit, 
                       bpc_poly<ppT> &polynomial);

}

#include <libsnark/zk_proof_systems/dario/components/polycommit/bpc.tcc>

#endif //BPC_HPP