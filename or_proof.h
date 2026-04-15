#ifndef OR_PROOF_H
#define OR_PROOF_H

#include <vector>
#include "Algorithm/pairing_3.h"
#include "multi_issuer.h"
#include "nizk_proof.h" 

using namespace std;

// 盲化后的凭证
struct BlindedCredential {
    AggregatedPK apk_prime; // apk_prime_x, apk_prime_Y
    G1 h_prime;
    G1 s_prime;
};

// OR-Proof 证明
struct ORProof {
    Big c_left;
    GT T_left;
    G1 z_h;
    G1 z_s;
    
    Big c_right;
    G2 T_right;
    Big z_right;
};

// 完整协议交互中用户发送给验证者的大礼包
struct PresentationPayload {
    ORProof proof;
    G2 pk_U;            // 用户公钥
    G2 pk_V;            // 验证者公钥
    vector<Big> m;      // 用户属性明文
    BlindedCredential cred;
};

// 辅助函数：计算 apk_{\Sigma}
G2 computeApkSigma(const AggregatedPK& apk, const vector<Big>& m, PFC* pfc);

// 用户生成完整展示的大礼包 (基于 OR-Proof 与随机化盲化凭证)
PresentationPayload generatePresentationPayload(
    const AggregatedPK& apk, 
    const SigShare& sig, 
    const vector<Big>& m, 
    const G2& pk_U, 
    const G2& pk_V, 
    PFC* pfc, 
    const G1& g, 
    const G2& g_tilde
);

// 验证方检查大礼包
bool verifyORProof(const PresentationPayload& payload, PFC* pfc, const G1& g, const G2& g_tilde);

// 验证方(拥有自己私钥 sk_V) 伪造大礼包以展现可否认性
PresentationPayload simulatePresentationPayloadByVerifier(
    const VerifierKeyPair& kp_V,
    const G2& pk_U,
    const vector<Big>& m, 
    PFC* pfc, 
    const G1& g, 
    const G2& g_tilde
);

#endif // OR_PROOF_H
