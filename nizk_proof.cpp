#include "nizk_proof.h"

// --- 生成验证者密钥对 ---
VerifierKeyPair generateVerifierKeyPair(PFC* pfc, const G2& G2_gen) {
    VerifierKeyPair kp;
    pfc->random(kp.sk_V);
    kp.pk_V = pfc->mult(G2_gen, kp.sk_V);
    return kp;
}

// --- 验证者生成NIZK证明 ---
NIZKProof generateNIZKProof(const string& id_V, const VerifierKeyPair& kp, PFC* pfc, const G2& G2_gen) {
    NIZKProof proof;
    
    // 第一步：承诺 (Commitment)
    Big k;
    pfc->random(k);
    G2 T = pfc->mult(G2_gen, k);
    
    // 第二步：挑战 (Challenge - Fiat-Shamir 转换)
    pfc->start_hash();
    pfc->add_to_hash((char*)id_V.c_str());
    pfc->add_to_hash(kp.pk_V);
    pfc->add_to_hash(T);
    proof.c = pfc->finish_hash_to_group() % pfc->order();
    
    // 第三步：响应 (Response)
    // z = k + c * sk_V mod p
    Big term = modmult(proof.c, kp.sk_V, pfc->order());
    proof.z = (k + term) % pfc->order();
    
    return proof;
}

// --- 用户校验NIZK证明 ---
bool verifyNIZKProof(const string& id_V, const G2& pk_V, const NIZKProof& proof, PFC* pfc, const G2& G2_gen) {
    // 第一步：重构承诺 T
    // T_reconstruct = g^z * pk_V^(-c) 
    // 在加法群中即为: z*G2_gen - c*pk_V
    
    // 计算 -c mod p
    Big neg_c = (pfc->order() - proof.c) % pfc->order();
    
    G2 term1 = pfc->mult(G2_gen, proof.z);
    G2 term2 = pfc->mult(pk_V, neg_c);
    
    G2 T_reconstruct = term1 + term2;
    
    // 第二步：哈希校验
    pfc->start_hash();
    pfc->add_to_hash((char*)id_V.c_str());
    pfc->add_to_hash(pk_V);
    pfc->add_to_hash(T_reconstruct);
    Big c_prime = pfc->finish_hash_to_group() % pfc->order();
    
    return proof.c == c_prime;
}
