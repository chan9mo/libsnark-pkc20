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
template<typename ppT>
class bpc_key;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const bpc_key<ppT> &ck);

template<typename ppT>
std::istream& operator>>(std::istream &in, bpc_key<ppT> &ck);

template <typename ppT>
class bpc_key
{
    public:
    int dimension;
    int length;
    libff::G2<ppT> g2;
    libff::G2<ppT> g2_s;
    libff::G1<ppT> h;
    libff::G1<ppT> h_s;
    libff::G2<ppT> g2_hat;
    libff::G1<ppT> h_hat;

    libff::G1_2dvector<ppT> g1_ij;
    libff::G1_2dvector<ppT> g1_hat_ij;

    bpc_key() = default;
    bpc_key<ppT>& operator=(const bpc_key<ppT> &other) = default;
    bpc_key(const bpc_key<ppT> &other) = default;
    bpc_key(bpc_key<ppT> &&other) = default;
    bpc_key(
        int dimension,
        int length,
        libff::G2<ppT> &&g2,
        libff::G2<ppT> &&g2_s,
        libff::G1<ppT> &&h,
        libff::G1<ppT> &&h_s,
        libff::G2<ppT> &&g2_hat,
        libff::G1<ppT> &&h_hat,
        libff::G1_2dvector<ppT> &&g1_ij,
        libff::G1_2dvector<ppT> &&g1_hat_ij) :
        
        dimension(dimension),
        length(length),
        g2(std::move(g2)),
        g2_s(std::move(g2_s)),
        h(std::move(h)),
        h_s(std::move(h_s)),
        g2_hat(std::move(g2_hat)),
        h_hat(std::move(h_hat)),
        g1_ij(std::move(g1_ij)),
        g1_hat_ij(std::move(g1_hat_ij)) {};        

    size_t G1_size() const
    {
        return 2;
    }

    size_t G2_size() const
    {
        return 1;
    }

    size_t size_in_bits() const
    {
       return G1_size() * libff::G1<ppT>::size_in_bits() + G2_size() * libff::G2<ppT>::size_in_bits();
    }

    void print_size() const
    {
        libff::print_indent(); printf("* G1 elements in CK: %zu\n", this->G1_size());
        libff::print_indent(); printf("* G2 elements in CK: %zu\n", this->G2_size());
        libff::print_indent(); printf("* CommitKey size in bits: %zu\n", this->size_in_bits());
    }


    bool operator==(const bpc_key<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const bpc_key<ppT> &ck);
    friend std::istream& operator>> <ppT>(std::istream &in, bpc_key<ppT> &ck);
};

/******************************** Commitment ********************************/
template<typename ppT>
class bpc_commit;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const bpc_commit<ppT> &commit);

template<typename ppT>
std::istream& operator>>(std::istream &in, bpc_commit<ppT> &commit);

template <typename ppT>
class bpc_commit
{
    public:
    libff::G1<ppT> commit;
    libff::G1<ppT> commit_hat;
    libff::Fr<ppT> rho;

    bpc_commit() = default;
    bpc_commit<ppT>& operator=(const bpc_commit<ppT> &other) = default;
    bpc_commit(const bpc_commit<ppT> &other) = default;
    bpc_commit(bpc_commit<ppT> &&other) = default;
    bpc_commit(
        libff::G1<ppT> &&commit,
        libff::G1<ppT> &&commit_hat,
        libff::Fr<ppT> &&rho) : 
            commit(std::move(commit)),
            commit_hat(std::move(commit_hat)),
            rho(std::move(rho)) {};

    size_t G1_size() const
    {
        return 2;
    }

    size_t G2_size() const
    {
        return 1;
    }

    size_t size_in_bits() const
    {
       return G1_size() * libff::G1<ppT>::size_in_bits() + G2_size() * libff::G2<ppT>::size_in_bits();
    }

    void print_size() const
    {
        libff::print_indent(); printf("* G1 elements in Commit: %zu\n", this->G1_size());
        libff::print_indent(); printf("* G2 elements in Commit: %zu\n", this->G2_size());
        libff::print_indent(); printf("* Commit size in bits: %zu\n", this->size_in_bits());
    }

    bool operator==(const bpc_commit<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const bpc_commit<ppT> &commit);
    friend std::istream& operator>> <ppT>(std::istream &in, bpc_commit<ppT> &commit);
};

/******************************** Polynomial ********************************/
// template <typename ppT>
// class bpc_unipoly
// {
//     public:
//     libff::G1_vector<ppT> coef;
//     libff::Fr<ppT> count;

//     bpc_unipoly(
//         libff::G1_vector<ppT> coef,
//         int count) :

//         coef(std::move(coef)),
//         count(std::move(count))
//         {};
// };


// template <typename ppT>
// class bpc_poly
// {
//     public:
//     libff::Fr_2dvector<ppT> coef;

//     bpc_poly(
//         libff::Fr_2dvector<ppT> coef) :
//         coef(std::move(coef))
//         {};
// };
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

// template <typename ppT>
// bpc_poly<ppT> mpc_to_bpc(bpc_unipoly<ppT> &polynomial);

/**
 * Commit: Outputs Commit, rho
 */

template <typename ppT>
bpc_commit<ppT> bpc_commitment(bpc_key<ppT> &ck, 
                           libff::Fr_2dvector<ppT> &polynomial);

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
                       libff::Fr_2dvector<ppT> &polynomial);

}

#include <libsnark/zk_proof_systems/dario/components/polycommit/bpc.tcc>

#endif //BPC_HPP