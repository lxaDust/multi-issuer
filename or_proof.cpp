#include "or_proof.h"

// --- 计算 apk_{\Sigma} = apk_x * \prod (apk_i)^{m_i} ---
G2 computeApkSigma(const AggregatedPK& apk, const vector<Big>& m, PFC* pfc) {
    G2 res = apk.X_agg;
    for (size_t i = 0; i < m.size(); i++) {
        G2 term = pfc->mult(apk.Y_agg[i], m[i]);
        res = res + term;
    }
    return res;
}

// --- 盲化凭证并生成数据 ---
BlindedCredential blindCredential(const AggregatedPK& apk, const SigShare& sig, Big r, PFC* pfc) {
    BlindedCredential bc;
    
    bc.apk_prime.X_agg = pfc->mult(apk.X_agg, r);
    for (size_t i = 0; i < apk.Y_agg.size(); i++) {
        bc.apk_prime.Y_agg.push_back(pfc->mult(apk.Y_agg[i], r));
    }
    
    bc.h_prime = pfc->mult(sig.h, r);
    Big r_sq = modmult(r, r, pfc->order());
    bc.s_prime = pfc->mult(sig.S, r_sq);
    return bc;
}

// --- 生成发送给验证者的数据包 ---
PresentationPayload generatePresentationPayload(
    const AggregatedPK& apk, 
    const SigShare& sig, 
    const vector<Big>& m, 
    const G2& pk_U, 
    const G2& pk_V, 
    PFC* pfc, 
    const G1& g, 
    const G2& g_tilde
) {
    PresentationPayload payload;
    payload.pk_U = pk_U;
    payload.pk_V = pk_V;
    payload.m = m;
    
    // 1. 签名与公钥的随机化
    Big r;
    pfc->random(r);
    payload.cred = blindCredential(apk, sig, r, pfc);
    G2 apk_sigma_prime = computeApkSigma(payload.cred.apk_prime, m, pfc);
    
    // 2. 模拟验证者私钥 (OR-Proof Right 侧伪造)
    ORProof proof;
    pfc->random(proof.c_right);
    pfc->random(proof.z_right);
    
    Big neg_c_right = (pfc->order() - proof.c_right) % pfc->order();
    // T_right = g_tilde^{z_right} + pk_V^{-c_right}
    proof.T_right = pfc->mult(g_tilde, proof.z_right) + pfc->mult(pk_V, neg_c_right);
    
    // 3. 证明拥有合法凭证 (OR-Proof Left 侧真实证明)
    Big r_h, r_s;
    pfc->random(r_h);
    pfc->random(r_s);
    
    G1 g_rh = pfc->mult(g, r_h);
    G1 g_rs = pfc->mult(g, r_s);
    
    // MIRACL 中的 pairing 参数约定为 e(G2, G1)
    proof.T_left = pfc->pairing(apk_sigma_prime, g_rh) * pfc->pairing(g_tilde, g_rs);
    
    // 4. 挑战分割与响应计算 (Fiat-Shamir)
    pfc->start_hash();
    pfc->add_to_hash(payload.cred.apk_prime.X_agg);
    pfc->add_to_hash(pk_U);
    pfc->add_to_hash(pk_V);
    for(size_t i = 0; i < m.size(); i++) {
        pfc->add_to_hash(m[i]);
    }
    pfc->add_to_hash(proof.T_left);
    pfc->add_to_hash(proof.T_right);
    
    Big c_total = pfc->finish_hash_to_group() % pfc->order();
    proof.c_left = lxor(c_total, proof.c_right);
    
    proof.z_h = pfc->mult(payload.cred.h_prime, proof.c_left) + g_rh;
    Big neg_c_left = (pfc->order() - proof.c_left) % pfc->order();
    proof.z_s = pfc->mult(payload.cred.s_prime, neg_c_left) + g_rs;
    
    payload.proof = proof;
    return payload;
}

// --- 验证方检查数据包 ---
bool verifyORProof(const PresentationPayload& payload, PFC* pfc, const G1& g, const G2& g_tilde) {
    const ORProof& proof = payload.proof;
    
    // 1. 挑战完整性：计算全局挑战 c_total
    pfc->start_hash();
    pfc->add_to_hash(payload.cred.apk_prime.X_agg);
    pfc->add_to_hash(payload.pk_U);
    pfc->add_to_hash(payload.pk_V);
    for(size_t i = 0; i < payload.m.size(); i++) {
        pfc->add_to_hash(payload.m[i]);
    }
    pfc->add_to_hash(proof.T_left);
    pfc->add_to_hash(proof.T_right);
    
    Big c_total = pfc->finish_hash_to_group() % pfc->order();
    Big computed_c_left = lxor(c_total, proof.c_right);
    
    if (computed_c_left != proof.c_left) {
        cout << "  -> [Debug] Challenge split check passed: " << (computed_c_left == proof.c_left) << endl;
        return false;
    }
    
    // 2. Right侧检查 (否认链路): g_tilde^{z_right} == T_right * pk_V^{c_right}
    G2 rhs2_left = pfc->mult(g_tilde, proof.z_right);
    G2 rhs2_right = proof.T_right + pfc->mult(payload.pk_V, proof.c_right);
    if (!(rhs2_left == rhs2_right)) {
        cout << "  -> [Debug] Right side check passed: " << (rhs2_left == rhs2_right) << endl;
        return false;
    }
    
    // 3. Left侧检查 (合法凭证证明链路): e(z_h, apk'_{\Sigma}) * e(z_s, g_tilde) == T_left
    G2 apk_sigma_prime = computeApkSigma(payload.cred.apk_prime, payload.m, pfc);
    
    GT lhs3_1 = pfc->pairing(apk_sigma_prime, proof.z_h);
    GT lhs3_2 = pfc->pairing(g_tilde, proof.z_s);
    GT lhs_total = lhs3_1 * lhs3_2;
    
    if (!(lhs_total == proof.T_left)) {
        cout << "  -> [Debug] Left side check passed: " << (lhs_total == proof.T_left) << endl;
        return false;
    }
    
    return true;
}

// --- 验证者利用私钥伪造数据包 (可否认性) ---
PresentationPayload simulatePresentationPayloadByVerifier(
    const VerifierKeyPair& kp_V,
    const G2& pk_U,
    const vector<Big>& m, 
    PFC* pfc, 
    const G1& g, 
    const G2& g_tilde
) {
    PresentationPayload payload;
    payload.pk_U = pk_U;
    payload.pk_V = kp_V.pk_V;
    payload.m = m;
    
    // 1. 凭空捏造随机变量 (Fake Randomization) 伪造盲化凭证
    pfc->random(payload.cred.h_prime);
    pfc->random(payload.cred.s_prime);
    pfc->random(payload.cred.apk_prime.X_agg);
    
    for (size_t i = 0; i < m.size(); i++) {
        G2 temp;
        pfc->random(temp);
        payload.cred.apk_prime.Y_agg.push_back(temp);
    }
    
    // 2. 模拟凭证侧 (Left 侧 - 伪造)
    ORProof proof;
    pfc->random(proof.c_left);
    pfc->random(proof.z_h);
    pfc->random(proof.z_s);
    
    G2 apk_sigma_prime = computeApkSigma(payload.cred.apk_prime, m, pfc);
    
    // 核心倒推：T_left = e(apk_sigma_prime, z_h) * e(g_tilde, z_s) (注意 MIRACL 是 e(G2, G1))
    proof.T_left = pfc->pairing(apk_sigma_prime, proof.z_h) * pfc->pairing(g_tilde, proof.z_s);
    
    // 3. 真实证明验证者私钥 (Right 侧 - 真实)
    Big k_right;
    pfc->random(k_right);
    proof.T_right = pfc->mult(g_tilde, k_right);
    
    // 4. 挑战拼接与运算 (Fiat-Shamir)
    pfc->start_hash();
    pfc->add_to_hash(payload.cred.apk_prime.X_agg);
    pfc->add_to_hash(payload.pk_U);
    pfc->add_to_hash(payload.pk_V);
    for(size_t i = 0; i < m.size(); i++) {
        pfc->add_to_hash(m[i]);
    }
    pfc->add_to_hash(proof.T_left);
    pfc->add_to_hash(proof.T_right);
    
    Big c_total = pfc->finish_hash_to_group() % pfc->order();
    
    // 巧妙的挑战反解：c_total = c_left ^ c_right -> c_right = c_total ^ c_left
    proof.c_right = lxor(c_total, proof.c_left);
    
    // 计算右侧真实响应：z_right = k_right + c_right * sk_V
    Big term = modmult(proof.c_right, kp_V.sk_V, pfc->order());
    proof.z_right = (k_right + term) % pfc->order();
    
    payload.proof = proof;
    return payload;
}
