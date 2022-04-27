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
template<typename ppT>
class dario_crs;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const dario_crs<ppT> &crs);

template<typename ppT>
std::istream& operator>>(std::istream &in, dario_crs<ppT> &crs);

template <typename ppT>
class dario_crs
{
    public:
    bpc_key<ppT> crs_bpc;
    lego_cp_snark_keypair<ppT> crs_lego;

    dario_crs() = default;
    dario_crs<ppT>& operator=(const dario_crs<ppT> &other) = default;
    dario_crs(const dario_crs<ppT> &other) = default;
    dario_crs(dario_crs<ppT> &&other) = default;
    dario_crs(
        bpc_key<ppT> &&crs_bpc,
        lego_cp_snark_keypair<ppT> &&crs_lego) :

            crs_bpc(std::move(crs_bpc)),
            crs_lego(std::move(crs_lego)) {};

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

    bool operator==(const dario_crs<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const dario_crs<ppT> &crs);
    friend std::istream& operator>> <ppT>(std::istream &in, dario_crs<ppT> &crs);
};

/******************************** dario_statement ********************************/
template<typename ppT>
class dario_statement;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const dario_statement<ppT> &statement);

template<typename ppT>
std::istream& operator>>(std::istream &in, dario_statement<ppT> &statement);

template <typename ppT>
class dario_statement
{
    public:
    bpc_commit<ppT> commit;
    libff::Fr_2dvector<ppT> pubpoly;

    dario_statement() = default;
    dario_statement<ppT>& operator=(const dario_statement<ppT> &other) = default;
    dario_statement(const dario_statement<ppT> &other) = default;
    dario_statement(dario_statement<ppT> &&other) = default;
    dario_statement(
        bpc_commit<ppT> &&commit,
        libff::Fr_2dvector<ppT> &&pubpoly) :

            commit(std::move(commit)),
            pubpoly(std::move(pubpoly)) {};

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

    bool operator==(const dario_statement<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const dario_statement<ppT> &st);
    friend std::istream& operator>> <ppT>(std::istream &in, dario_statement<ppT> &st);
};

/******************************** dario_witness ********************************/
template<typename ppT>
class dario_witness;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const dario_witness<ppT> &witness);

template<typename ppT>
std::istream& operator>>(std::istream &in, dario_witness<ppT> &witness);

template <typename ppT>
class dario_witness
{
    public:
    libff::Fr_2dvector<ppT> polys;
    libff::Fr_2dvector<ppT> Tpoly;
    libff::Fr<ppT> rho;

    dario_witness() = default;
    dario_witness<ppT>& operator=(const dario_witness<ppT> &other) = default;
    dario_witness(const dario_witness<ppT> &other) = default;
    dario_witness(dario_witness<ppT> &&other) = default;
    dario_witness(
        libff::Fr_2dvector<ppT> &&polys,
        libff::Fr_2dvector<ppT> &&Tpoly,
        libff::Fr<ppT> &&rho) :

            polys(std::move(polys)),
            Tpoly(std::move(Tpoly)),
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

    bool operator==(const dario_witness<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const dario_witness<ppT> &wit);
    friend std::istream& operator>> <ppT>(std::istream &in, dario_witness<ppT> &wit);
};

/******************************** dario_proof ********************************/
template<typename ppT>
class dario_proof;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const dario_proof<ppT> &proof);

template<typename ppT>
std::istream& operator>>(std::istream &in, dario_proof<ppT> &proof);

template <typename ppT>
class dario_proof
{
    public:
    bpc_commit<ppT> commitT; // = bpc_commit<ppT>();
    bpc_commit<ppT> commit_prime;// = bpc_commit<ppT>();
    lego_cp_snark_proof<ppT> proof_lego;// = lego_cp_snark_proof<ppT>();
    bpe_proof<ppT> proof_mue;// = bpe_proof<ppT>();


    dario_proof() {};
    dario_proof(
        bpc_commit<ppT> &&commitT,
        bpc_commit<ppT> &&commit_prime,
        lego_cp_snark_proof<ppT> &&proof_lego,
        bpe_proof<ppT> &&proof_mue) :

            commitT(std::move(commitT)),
            commit_prime(std::move(commit_prime)),
            proof_lego(std::move(proof_lego)),
            proof_mue(std::move(proof_mue)) {};

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
        return (commitT.is_well_formed() &&
                commit_prime.is_well_formed() &&
                proof_lego.is_well_formed() &&
                proof_mue.is_well_formed());
    }

    bool operator==(const dario_proof<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const dario_proof<ppT> &proof);
    friend std::istream& operator>> <ppT>(std::istream &in, dario_proof<ppT> &proof);

};

/******************************** Main Algorithms ********************************/

/**
 * Generator: Outputs crs
 */
template<typename ppT>
dario_crs<ppT> crs_generator(int &dimension,
                       int &length,
                       dario_constraint_system<ppT> &r1cs,
                       dario_primary_input<ppT> &primary_input,
                       relation<ppT> &R_link);  
// /**
//  * Polynomial Evaluation
//  */
// template<typename ppT>
// libff::Fr<ppT> poly_eval(libff::Fr_2dvector<ppT> &poly, 
//                          libff::Fr<ppT> &point);

/**
 * Prover: Outputs dario_proof
 */
template<typename ppT>
dario_proof<ppT> dario_prover(dario_crs<ppT> &crs,
                        dario_statement<ppT> &st,
                        dario_witness<ppT> &wit,
                        dario_primary_input<ppT> &primary_input);          

/**
 * Verifier: Verifies dario_proof
 */
template <typename ppT>
bool dario_verifier(dario_crs<ppT> &crs,
              dario_statement<ppT> &st,
              dario_proof<ppT> &dario_proof);
}

#include <libsnark/zk_proof_systems/dario/dario.tcc>

#endif