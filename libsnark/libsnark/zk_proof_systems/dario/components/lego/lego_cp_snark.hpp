#ifndef LEGO_CP_SNARK_HPP_
#define LEGO_CP_SNARK_HPP_

#include <memory>

#include <libff/algebra/curves/public_params.hpp>

#include <libsnark/common/data_structures/accumulation_vector.hpp>
#include <libsnark/knowledge_commitment/knowledge_commitment.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark_params.hpp>
#include <libsnark/zk_proof_systems/dario/components/lego/lego_ss.hpp>

namespace libsnark
{
template <typename ppT>
class statement;

template <typename ppT>
class statement
{
public:
    libff::G1_vector<ppT> commitments;
    libff::G1<ppT> commitment_prime;

    size_t commit_num() const
    {
        return commitments.size();
    }

    statement() = default;
    statement(const statement<ppT> &other) = default;
    statement(statement<ppT> &other) = default;
    statement(libff::G1_vector<ppT> &&commitments,
              libff::G1<ppT> &&commitment_prime) :
              commitments(std::move(commitments)),
              commitment_prime(std::move(commitment_prime))
    {};

    void print() const;
};

template <typename ppT>
class witness;

template <typename ppT>
class witness
{
public:
    libff::Fr_vector<ppT> openings;
    libff::Fr<ppT> opening_prime;

    witness() = default;
    witness(const witness<ppT> &other) = default;
    witness(witness<ppT> &other) = default;
    witness(libff::Fr_vector<ppT> &&openings,
            libff::Fr<ppT> &&opening_prime) :
            openings(std::move(openings)),
            opening_prime(std::move(opening_prime))
    {};

    void print() const;
};

template <typename ppT>
class relation;

template <typename ppT>
class relation
{
public:
    statement<ppT> state;
    witness<ppT> wit;

    relation() = default;
    relation(const relation<ppT> &other) = default;
    relation(relation<ppT> &other) = default;
    relation(statement<ppT> &&stat,
             witness<ppT> &&wi) :
             state(std::move(stat)), wit(std::move(wi)) {};

    void print() const;
};

/********************* Evaluation Key *********************/
template <typename ppT>
class lego_cp_snark_evaluation_key;

template <typename ppT>
std::ostream &operator<<(std::ostream &out, const lego_cp_snark_evaluation_key<ppT> &ek);

template <typename ppT>
std::istream &operator>>(std::istream &in, lego_cp_snark_evaluation_key<ppT> &ek);

template <typename ppT>
class lego_cp_snark_evaluation_key
{
public:
    lego_ss_evaluation_key<ppT> ek;

    lego_cp_snark_evaluation_key() = default;
    lego_cp_snark_evaluation_key(const lego_cp_snark_evaluation_key<ppT> &other) = default;

    void print() const;
};

/********************* Verification Key *********************/
template <typename ppT>
class lego_cp_snark_verification_key;

template <typename ppT>
std::ostream &operator<<(std::ostream &out, const lego_cp_snark_verification_key<ppT> &vk);

template <typename ppT>
std::istream &operator>>(std::istream &in, lego_cp_snark_verification_key<ppT> &vk);

template <typename ppT>
class lego_cp_snark_verification_key
{
public:
    lego_ss_verification_key<ppT> vk;

    lego_cp_snark_verification_key() = default;
    lego_cp_snark_verification_key(const lego_cp_snark_verification_key<ppT> &other) = default;

    void print() const;
};

/************************ Key Pair ************************/
template <typename ppT>
class lego_cp_snark_keypair;

template <typename ppT>
std::ostream &operator<<(std::ostream &out, const lego_cp_snark_keypair<ppT> &pair);

template <typename ppT>
std::istream &operator>>(std::istream &in, lego_cp_snark_keypair<ppT> &pair);

template <typename ppT>
class lego_cp_snark_keypair
{
public:
    lego_cp_snark_evaluation_key<ppT> ek;
    lego_cp_snark_verification_key<ppT> vk;

    lego_cp_snark_keypair() = default;
    lego_cp_snark_keypair(const lego_cp_snark_keypair<ppT> &other) = default;
    lego_cp_snark_keypair(const lego_cp_snark_evaluation_key<ppT> &&ek,
                          const lego_cp_snark_verification_key<ppT> &&vk) :
                          ek(std::move(ek)), vk(std::move(vk)) {};
    lego_cp_snark_keypair(const lego_ss_evaluation_key<ppT> &ek,
                          const lego_ss_verification_key<ppT> &vk);

    void print() const;
};

/************************** Proof **************************/
template <typename ppT>
class lego_cp_snark_proof;

template <typename ppT>
std::ostream &operator<<(std::ostream &out, const lego_cp_snark_proof<ppT> &proof);

template <typename ppT>
std::istream &operator>>(std::istream &in, lego_cp_snark_proof<ppT> &proof);

template <typename ppT>
class lego_cp_snark_proof
{
public:
    lego_ss_proof<ppT> proof;

    lego_cp_snark_proof() = default;
    lego_cp_snark_proof(const lego_cp_snark_proof<ppT> &other) = default;

    void print() const;
};

/********************* Main Algorithms *********************/
// keygen, prove, verproof
template <typename ppT>
lego_cp_snark_keypair<ppT> lego_cp_snark_generator(const r1cs_gg_ppzksnark_constraint_system<ppT> &r1cs,
                                                   const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input,
                                                   relation<ppT> &R_link);
template <typename ppT>
lego_cp_snark_proof<ppT> lego_cp_snark_prover(const lego_cp_snark_evaluation_key<ppT> &ek,
                                              const relation<ppT> &R_link,
                                              const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input);

template <typename ppT>
bool lego_cp_snark_verifier(const lego_cp_snark_verification_key<ppT> &vk,
                            const statement<ppT> &state,
                            const lego_cp_snark_proof<ppT> &proof);

template <typename ppT>
relation<ppT> make_commitment(const libff::G1_vector<ppT> &h_vector,
                              const accumulation_vector<libff::G1<ppT>> &f_vector,
                              const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input);

} // namespace libsnark

#include <libsnark/zk_proof_systems/dario/components/lego/lego_cp_snark.tcc>

#endif // LEGO_CP_SNARK_HPP_
