#include "trusted_authority.h"
#include <chrono>
#include <iostream>

// --- 生成TA密钥对 ---
TAKeyPair generateTAKeyPair(int num_messages, PFC* pfc, const G1& G1_gen) {
    TAKeyPair kp;
    
    // 生成私钥
    pfc->random(kp.sk.x_TA);
    pfc->random(kp.sk.y_x);
    
    // 生成公钥
    kp.pk.X = pfc->mult(G1_gen, kp.sk.x_TA);
    kp.pk.Y_x = pfc->mult(G1_gen, kp.sk.y_x);
    
    for (int i = 0; i < num_messages; i++) {
        Big y_i;
        pfc->random(y_i);
        kp.sk.y.push_back(y_i);
        
        G1 Y_i = pfc->mult(G1_gen, y_i);
        kp.pk.Y.push_back(Y_i);
    }
    
    return kp;
}

// --- TA生成随机化签名 ---
TASignature signAggregatedPK(const TAKeyPair& ta_kp, const AggregatedPK& apk, PFC* pfc, const G2& G2_gen) {
    TASignature sig;
    
    // TA选取随机盲化因子 ρ (rho)
    Big rho;
    pfc->random(rho);
    
    // 计算随机化基点 R = ρ * G2_gen (在 MIRACL中对应 R = G2_gen^ρ)
    sig.R = pfc->mult(G2_gen, rho);
    
    // 计算核心签名组件 S = x_{TA} * R + y_x * apk_x + \sum (y_i * apk_i)
    sig.S = pfc->mult(sig.R, ta_kp.sk.x_TA);
    
    G2 term_x = pfc->mult(apk.X_agg, ta_kp.sk.y_x);
    sig.S = sig.S + term_x;
    
    for (size_t i = 0; i < apk.Y_agg.size(); i++) {
        G2 term_i = pfc->mult(apk.Y_agg[i], ta_kp.sk.y[i]);
        sig.S = sig.S + term_i;
    }
    
    return sig;
}

// --- 用户的盲化操作 (Randomize) ---
RandomizedCredential randomizeCredential(const AggregatedPK& apk, const TASignature& sig, PFC* pfc) {
    RandomizedCredential cred;
    
    // 选取全新的随机数 r
    Big r;
    pfc->random(r);
    
    // 盲化聚合公钥: apk'_x = r * apk_x,  apk'_i = r * apk_i
    cred.apk_x_prime = pfc->mult(apk.X_agg, r);
    for (size_t i = 0; i < apk.Y_agg.size(); i++) {
        cred.apk_Y_prime.push_back(pfc->mult(apk.Y_agg[i], r));
    }
    
    // 盲化签名: R' = r * R, S' = r * S
    cred.R_prime = pfc->mult(sig.R, r);
    cred.S_prime = pfc->mult(sig.S, r);
    
    return cred;
}

// --- 第三方验证过程 ---
bool verifyRandomizedCredential(const TAPublicKey& ta_pk, const RandomizedCredential& cred, PFC* pfc, const G1& G1_gen) {
    auto start_time = std::chrono::high_resolution_clock::now();

    // 验证者检查双线性配对等式是否成立:
    // e(g, S') = e(X, R') * e(Y_x, apk'_x) * \prod e(Y_i, apk'_i)
    
    // 由于 MIRACL pfc->pairing 约定为 e(G2, G1)，我们需要将顺序调整好：
    // e(S_prime, G1_gen)
    GT lhs = pfc->pairing(cred.S_prime, G1_gen);
    
    // e(R_prime, X)
    GT rhs = pfc->pairing(cred.R_prime, ta_pk.X);
    
    // * e(apk'_x, Y_x)
    rhs = rhs * pfc->pairing(cred.apk_x_prime, ta_pk.Y_x);
    
    // * \prod e(apk'_i, Y_i)
    for (size_t i = 0; i < cred.apk_Y_prime.size(); i++) {
        rhs = rhs * pfc->pairing(cred.apk_Y_prime[i], ta_pk.Y[i]);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    std::cout << "[Time] verifyRandomizedCredential execution time: " << duration << " ms" << std::endl;

    return lhs == rhs;
}
