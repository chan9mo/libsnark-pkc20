#ifndef LEGO_SS_HPP_
#define LEGO_SS_HPP_

#include <memory>

#include <libff/algebra/curves/public_params.hpp>

#include <libsnark/common/data_structures/accumulation_vector.hpp>
#include <libsnark/knowledge_commitment/knowledge_commitment.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark_params.hpp>

namespace libsnark
{
    /********************* Evaluation Key *********************/
    template <typename ppT>
    class lego_ss_evaluation_key;

    template <typename ppT>
    std::ostream &operator<<(std::ostream &out, const lego_ss_evaluation_key<ppT> &ek);

    template <typename ppT>
    std::istream &operator>>(std::istream &in, lego_ss_evaluation_key<ppT> &ek);

    template <typename ppT>
    class lego_ss_evaluation_key
    {
    public:
        libff::G1_vector<ppT> g1_P;

        lego_ss_evaluation_key() = default;
        lego_ss_evaluation_key<ppT>& operator=(const lego_ss_evaluation_key<ppT> &other) = default;
        lego_ss_evaluation_key(const libff::G1_vector<ppT> &&g1_P) :
                               g1_P(std::move(g1_P)) {};

        void print() const;
    };

    /********************* Verification Key *********************/
    template <typename ppT>
    class lego_ss_verification_key;

    template <typename ppT>
    std::ostream &operator<<(std::ostream &out, const lego_ss_verification_key<ppT> &vk);

    template <typename ppT>
    std::istream &operator>>(std::istream &in, lego_ss_verification_key<ppT> &vk);

    template <typename ppT>
    class lego_ss_verification_key
    {
    public:
        libff::G2<ppT> g2_a;

        libff::G2_vector<ppT> g2_C;

        lego_ss_verification_key() = default;
        lego_ss_verification_key<ppT>& operator=(const lego_ss_verification_key<ppT> &other) = default;
        lego_ss_verification_key(const libff::G2<ppT> &&g2_a,
                                 const libff::G2_vector<ppT> &&g2_C) :
                                 g2_a(std::move(g2_a)), g2_C(std::move(g2_C)) {};
    
        void print() const;
    };

    /************************ Key Pair ************************/
    template <typename ppT>
    class lego_ss_keypair;

    template <typename ppT>
    std::ostream &operator<<(std::ostream &out, const lego_ss_keypair<ppT> &pair);

    template <typename ppT>
    std::istream &operator>>(std::istream &in, lego_ss_keypair<ppT> &pair);

    template <typename ppT>
    class lego_ss_keypair
    {
    public:
        lego_ss_evaluation_key<ppT> ek;
        lego_ss_verification_key<ppT> vk;

        lego_ss_keypair() = default;
        lego_ss_keypair<ppT>& operator=(const lego_ss_keypair<ppT> &other) = default;
        lego_ss_keypair(const lego_ss_keypair<ppT> &other) = default;
        lego_ss_keypair(const lego_ss_evaluation_key<ppT> &&ek,
                        const lego_ss_verification_key<ppT> &&vk) :
                        ek(std::move(ek)), vk(std::move(vk)) {};
    
        void print() const;
    };

    /************************** Proof **************************/
    template <typename ppT>
    class lego_ss_proof;

    template <typename ppT>
    std::ostream &operator<<(std::ostream &out, const lego_ss_proof<ppT> &proof);

    template <typename ppT>
    std::istream &operator>>(std::istream &in, lego_ss_proof<ppT> &proof);

    template <typename ppT>
    class lego_ss_proof
    {
    public:
        libff::G1<ppT> g1_pi;

        lego_ss_proof() = default;
        lego_ss_proof(const libff::G1<ppT> g1_pi) :
                      g1_pi(g1_pi) {};
    
        void print() const;
    };

    /********************* Main Algorithms *********************/
    template <typename ppT>
    lego_ss_keypair<ppT> lego_ss_generator(const libff::G1_vector<ppT> &M,
                                           const size_t &l,
                                           const size_t &t);

    template <typename ppT>
    lego_ss_proof<ppT> lego_ss_prover(const lego_ss_evaluation_key<ppT> &ek,
                                      const libff::G1_vector<ppT> &x,
                                      const libff::Fr_vector<ppT> &w);

    template <typename ppT>
    bool lego_ss_verifier(const lego_ss_verification_key<ppT> &vk,
                          const libff::G1_vector<ppT> &x, 
                          const lego_ss_proof<ppT> &proof);

} // namespace libsnark

#include <libsnark/zk_proof_systems/dario/components/lego/lego_ss.tcc>

#endif // LEGO_SS_HPP_
