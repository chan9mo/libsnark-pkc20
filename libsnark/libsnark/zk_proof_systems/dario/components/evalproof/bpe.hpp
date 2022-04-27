/** @file
*****************************************************************************

Declaration of interfaces for a Polyomial Evaluation SNARK in QPP Model.

This includes:
- CRS (common random string): BPC의 commitment key를 그대로 쓰면 된다.
- class for statement
- class for polynomial
- class for witness
- class for proof
- generator algorithm: BPC.Generator를 그래도 쓰면 된다.
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

#ifndef BPE_HPP_
#define BPE_HPP_

#include <memory>

#include <libff/algebra/curves/public_params.hpp>
#include <libsnark/common/data_structures/accumulation_vector.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/knapsack/knapsack_gadget.hpp>
#include <libsnark/knowledge_commitment/knowledge_commitment.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark_params.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/dario/components/polycommit/bpc.hpp>

namespace libsnark
{

/******************************** Statement ********************************/
template<typename ppT>
class bpe_statement;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const bpe_statement<ppT> &statement);

template<typename ppT>
std::istream& operator>>(std::istream &in, bpe_statement<ppT> &statement);


template <typename ppT>
class bpe_statement
{
    public:
    bpc_commit<ppT> commit;
    bpc_commit<ppT> commit_prime;
    libff::Fr<ppT> point;

    bpe_statement() = default;
    bpe_statement<ppT>& operator=(const bpe_statement<ppT> &other) = default;
    bpe_statement(const bpe_statement<ppT> &other) = default;
    bpe_statement(bpe_statement<ppT> &&other) = default;
    bpe_statement(
        bpc_commit<ppT> &&commit,
        bpc_commit<ppT> &&commit_prime,
        libff::Fr<ppT> &&point) :

            commit(std::move(commit)),
            commit_prime(std::move(commit_prime)),
            point(std::move(point)) {};

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

    bool operator==(const bpe_statement<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const bpe_statement<ppT> &commit);
    friend std::istream& operator>> <ppT>(std::istream &in, bpe_statement<ppT> &commit);
};

/******************************** Polynomial ********************************/
/* BPC Poly를 사용
template <typename ppT>
class bpe_poly
{
    public:
    libff::Fr_2dvector<ppT> coef;

    libff::Fr_2dvector(
        libff::Fr_2dvector<ppT> &&coef) :
        coef(std::move(coef)) {};
};
vector를 원소로 가지는 vector */

/******************************** Witness ********************************/
template<typename ppT>
class bpe_witness;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const bpe_witness<ppT> &witness);

template<typename ppT>
std::istream& operator>>(std::istream &in, bpe_witness<ppT> &witness);

template <typename ppT>
class bpe_witness
{
    public:
    libff::Fr_2dvector<ppT> Ppoly;
    libff::Fr_2dvector<ppT> Qpoly;
    libff::Fr<ppT> rho;
    libff::Fr<ppT> rho_prime;

    bpe_witness() = default;
    bpe_witness<ppT>& operator=(const bpe_witness<ppT> &other) = default;
    bpe_witness(const bpe_witness<ppT> &other) = default;
    bpe_witness(bpe_witness<ppT> &&other) = default;
    bpe_witness(
        libff::Fr_2dvector<ppT> &&Ppoly,
        libff::Fr_2dvector<ppT> &&Qpoly,
        libff::Fr<ppT> &&rho,
        libff::Fr<ppT> &&rho_prime) :

        Ppoly(std::move(Ppoly)),
        Qpoly(std::move(Qpoly)),
        rho(std::move(rho)),
        rho_prime(std::move(rho_prime)) {};

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

    bool operator==(const bpe_witness<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const bpe_witness<ppT> &witness);
    friend std::istream& operator>> <ppT>(std::istream &in, bpe_witness<ppT> &witness);
};

/******************************** Proof ********************************/
template<typename ppT>
class bpe_proof;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const bpe_proof<ppT> &proof);

template<typename ppT>
std::istream& operator>>(std::istream &in, bpe_proof<ppT> &proof);

template <typename ppT>
class bpe_proof
{
    public:
    bpc_commit<ppT> commit;
    int hash;
    libff::Fr<ppT> sigma;
    libff::Fr<ppT> tau;

    bpe_proof() = default;
    bpe_proof<ppT>& operator=(const bpe_proof<ppT> &other) = default;
    bpe_proof(const bpe_proof<ppT> &other) = default;
    bpe_proof(bpe_proof<ppT> &&other) = default;
    bpe_proof(
        bpc_commit<ppT> &&commit,
        int hash,
        libff::Fr<ppT> &&sigma,
        libff::Fr<ppT> &&tau) :

        commit(std::move(commit)),
        hash(hash),
        sigma(std::move(sigma)),
        tau(std::move(tau)) {};

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

    bool is_well_formed() const
    {
        return (commit.is_well_formed() &&
                sigma.is_well_formed() &&
                tau.is_well_formed());
    }

    bool operator==(const bpe_proof<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const bpe_proof<ppT> &commit);
    friend std::istream& operator>> <ppT>(std::istream &in, bpe_proof<ppT> &commit);
};

/***************************** Main algorithms ******************************/

/**
 * Prover: Outputs Proof
 */

template <typename ppT>
bpe_proof<ppT> bpe_prover(bpc_key<ppT> &crs, 
                          bpe_statement<ppT> &u,
                          bpe_witness<ppT> &w);

/**
 * Verifier: Verifies Proof
 */
template <typename ppT>
bool bpe_verifier(bpc_key<ppT> &crs, 
                  bpe_statement<ppT> &u,
                  bpe_proof<ppT> &proof);

}

#include <libsnark/zk_proof_systems/dario/components/evalproof/bpe.tcc>

#endif //BPE_HPP