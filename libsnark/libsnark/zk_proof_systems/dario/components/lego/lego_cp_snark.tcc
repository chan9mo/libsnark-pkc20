#ifndef LEGO_CP_SNARK_TCC_
#define LEGO_CP_SNARK_TCC_

#include <algorithm>
#include <cassert>
#include <functional>
#include <iostream>
#include <sstream>

#include <libff/algebra/scalar_multiplication/multiexp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#include <libsnark/knowledge_commitment/kc_multiexp.hpp>
#include <libsnark/reductions/r1cs_to_qap/r1cs_to_qap.hpp>
#include <libsnark/zk_proof_systems/dario/components/lego/lego_cp_snark.hpp>
#include <libsnark/zk_proof_systems/dario/components/lego/r1cs_gg_ppzksnark.hpp>

namespace libsnark
{
    template <typename ppT>
    void statement<ppT>::print() const
    {
        libff::print_indent(); printf("* Commitments : \n");
        this->commitments.print();
        libff::print_indent(); printf("* Commit prime : \n");
        this->commitment_prime.print();
    }

    template <typename ppT>
    void witness<ppT>::print() const
    {
        libff::print_indent(); printf("* Openings : \n");
        this->openings.print();
        libff::print_indent(); printf("* Opening prime : \n");
        this->opening_prime.print();
    }

    template <typename ppT>
    void relation<ppT>::print() const
    {
        this->state.print();
        this->wit.print();
    }

    template <typename ppT>
    void lego_cp_snark_evaluation_key<ppT>::print() const
    {
        libff::print_indent(); printf("* lego_cp_snark_evaluation_key : ");
        this->ek.print();
    }

    template <typename ppT>
    void lego_cp_snark_verification_key<ppT>::print() const
    {
        libff::print_indent(); printf("* lego_cp_snark_verification_key : ");
        this->vk.print();
    }

    template <typename ppT>
    void lego_cp_snark_keypair<ppT>::print() const
    {
        this->ek.print();
        this->vk.print();
    }

    template <typename ppT>
    void lego_cp_snark_proof<ppT>::print() const
    {
        libff::print_indent(); printf("* lego_cp_snark_proof :");
        this->proof.print();
    }

    template <typename ppT>
    std::ostream &operator<<(std::ostream &out, const lego_cp_snark_evaluation_key<ppT> &ek)
    {
        out << ek.ek << OUTPUT_NEWLINE;

        return out;
    }

    template <typename ppT>
    std::istream &operator>>(std::istream &in, lego_cp_snark_evaluation_key<ppT> &ek)
    {
        in >> ek.ek;
        libff::consume_OUTPUT_NEWLINE(in);

        return in;
    }

    template <typename ppT>
    std::ostream &operator<<(std::ostream &out, const lego_cp_snark_verification_key<ppT> &vk)
    {
        out << vk.vk << OUTPUT_NEWLINE;

        return out;
    }

    template <typename ppT>
    std::istream &operator>>(std::istream &in, lego_cp_snark_verification_key<ppT> &vk)
    {
        in >> vk.vk;
        libff::consume_OUTPUT_NEWLINE(in);

        return in;
    }

    template <typename ppT>
    std::ostream &operator<<(std::ostream &out, const lego_cp_snark_keypair<ppT> &pair)
    {
        out << pair.ek << OUTPUT_NEWLINE;
        out << pair.vk << OUTPUT_NEWLINE;

        return out;
    }

    template <typename ppT>
    std::istream &operator>>(std::istream &in, lego_cp_snark_keypair<ppT> &pair)
    {
        in >> pair.vk;
        libff::consume_OUTPUT_NEWLINE(in);
        in >> pair.vk;
        libff::consume_OUTPUT_NEWLINE(in);

        return in;
    }

    template <typename ppT>
    std::ostream &operator<<(std::ostream &out, const lego_cp_snark_proof<ppT> &proof)
    {
        out << proof.proof << OUTPUT_NEWLINE;

        return out;
    }

    template <typename ppT>
    std::istream &operator>>(std::istream &in, lego_cp_snark_proof<ppT> &proof)
    {
        in >> proof.proof;
        libff::consume_OUTPUT_NEWLINE(in);

        return in;
    }

    template <typename ppT>
    lego_cp_snark_keypair<ppT>::lego_cp_snark_keypair(const lego_ss_evaluation_key<ppT> &ek,
                                                      const lego_ss_verification_key<ppT> &vk)
    {
        this->ek.ek = ek;
        this->vk.vk = vk;
    }

    template <typename ppT>
    relation<ppT> make_commitment(const libff::G1_vector<ppT> &h_vector,
                                  const accumulation_vector<libff::G1<ppT>> &f_vector,
                                  const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input)
    {
        libff::enter_block("Call to make_commitment");
        relation<ppT> R_link;
        // 1 commitment
        R_link.state.commitments.reserve(1);
        R_link.wit.openings.reserve(1);
        R_link.wit.openings.emplace_back(libff::Fr<ppT>::random_element());
        R_link.wit.opening_prime = libff::Fr<ppT>::random_element();
        size_t l = h_vector.size();
        R_link.state.commitments.emplace_back(R_link.wit.openings[0] * h_vector[0]);
        R_link.state.commitment_prime = R_link.wit.opening_prime * f_vector.first;
        for (size_t i = 1; i < l; i++)
        {
            R_link.state.commitments[0] = R_link.state.commitments[0] + primary_input[i - 1] * h_vector[i];
            R_link.state.commitment_prime = R_link.state.commitment_prime + primary_input[i - 1] * f_vector.rest[i - 1];
        }
        // R_link.print();

        libff::leave_block("Call to make_commitment");
        
        return R_link;
    }

    template <typename ppT>
    lego_cp_snark_keypair<ppT> lego_cp_snark_generator(const r1cs_gg_ppzksnark_constraint_system<ppT> &r1cs,
                                                       const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input,
                                                       relation<ppT> &R_link)
    {
        libff::enter_block("Call to lego_cp_snark_generator");

        libff::G1_vector<ppT> h; // ck
        lego_ss_keypair<ppT> ss_pair; // (ek, vk) where ek:=[P] = M^T * k and vk:=([C], [a]) s.t.  C = a*k 
        libff::G1_vector<ppT> M; // Matrix M where [x]:=[M]*[w] (x is statement and w is witness, the openings)
        r1cs_gg_ppzksnark_constraint_system<ppT> r1cs_copy(r1cs);

        // get accumulation f from gro16 keypair
        r1cs_gg_ppzksnark_keypair<ppT> gro16_keypair = r1cs_gg_ppzksnark_generator<ppT>(r1cs_copy); 
        accumulation_vector<libff::G1<ppT>> ck_prime = gro16_keypair.vk.gamma_ABC_g1; 

        size_t l = primary_input.size();
        h.reserve(l + 1);
        M.reserve(2 * l + 4); 

        // h vector random generation
        for (size_t i = 0; i < l + 1; i++)
        {
            h.emplace_back(libff::G1<ppT>::random_element());
        }

        M.emplace_back(h[0]);
        M.emplace_back(libff::G1<ppT>::zero());
        for (size_t i = 1; i < l + 1; i++)
        {
            M.emplace_back(h[i]);
        }
        M.emplace_back(libff::G1<ppT>::zero());
        M.emplace_back(ck_prime.first);
        for (size_t i = 0; i < l; i++)
        {
            M.emplace_back(ck_prime.rest[i]);
        }
        ss_pair = lego_ss_generator<ppT>(M, 2, l + 2);

        ss_pair.print();

        R_link = make_commitment<ppT>(h, ck_prime, primary_input);
        
        libff::leave_block("Call to lego_cp_snark_generator");
        return lego_cp_snark_keypair<ppT>(ss_pair.ek, ss_pair.vk);
    }

    template <typename ppT>
    lego_cp_snark_proof<ppT> lego_cp_snark_prover(const lego_cp_snark_evaluation_key<ppT> &ek,
                                                  const relation<ppT> &R_link,
                                                  const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input)
    {
        libff::enter_block("Call to lego_cp_snark_prover");
        lego_cp_snark_proof<ppT> proof;
        libff::G1_vector<ppT> x;
        libff::Fr_vector<ppT> w;
        size_t l = primary_input.size();
        x.reserve(2);
        w.reserve(l + 2);
        libff::enter_block("Generating vector x");
        x.emplace_back(R_link.state.commitments[0]);
        x.emplace_back(R_link.state.commitment_prime);
        libff::leave_block("Generated vector x");

        w.emplace_back(R_link.wit.openings[0]);
        w.emplace_back(R_link.wit.opening_prime);

        for (size_t i = 0; i < l; i++)
        {
            w.emplace_back(primary_input[i]);
        }
        proof.proof = lego_ss_prover<ppT>(ek.ek, x, w);

        libff::leave_block("Call to lego_cp_snark_prover");
        return proof;
    }

    template <typename ppT>
    bool lego_cp_snark_verifier(const lego_cp_snark_verification_key<ppT> &vk,
                                const statement<ppT> &state,
                                const lego_cp_snark_proof<ppT> &proof)
    {
        libff::enter_block("Call to lego_cp_snark_verifier");
        libff::G1_vector<ppT> x;
        x.reserve(2);
        x.emplace_back(state.commitments[0]);
        x.emplace_back(state.commitment_prime);
        libff::leave_block("Call to lego_cp_snark_verifier");
        return lego_ss_verifier<ppT>(vk.vk, x, proof.proof);
    }

} // namespace libsnark

#endif