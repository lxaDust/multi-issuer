#include <iostream>
#include <vector>
#include "Algorithm/pairing_3.h"
#include "multi_issuer.h"
#include "trusted_authority.h"
#include "nizk_proof.h"
#include "or_proof.h"

using namespace std;

int main() {
    PFC pfc(128); // 128-bit security BN curve 环境初始化
    {
        G2 G2_gen;
        pfc.random(G2_gen); // G2 上的全局基点
        
        G1 G1_gen;
        pfc.random(G1_gen); // G1 上的全局基点
        
        int num_messages = 2; 
        vector<Big> messages = {Big(12345), Big(67890)}; // 用户的一些属性信息
        
        cout << "=== PS 多签发方协作签发证书实验演示 ===" << endl;
        
        // 将用户信息哈希到 G1 上的点 h (由于演示目的，直接在群上随机取点模拟哈希过程)
        G1 h;
        pfc.random(h);
        cout << "-> 用户生成其属性信息的哈希点 h (在群 G1 上)" << endl;
        
        cout << "\n[1] 各方生成各自的密钥对..." << endl;
        
        cout << "  -> 签名发起方生成自己的密钥对..." << endl;
        KeyPair kp_initiator = generateKeyPair(num_messages, &pfc, G2_gen);
        
        cout << "  -> 【要求满足】签名发起方为虚拟用户 dm 生成 dm 的密钥对..." << endl;
        KeyPair kp_dm = generateKeyPair(num_messages, &pfc, G2_gen); 
        
        int num_other_issuers = 3;
        cout << "  -> " << num_other_issuers << " 个其他合作签发方生成各自的密钥对..." << endl;
        
        vector<KeyPair> other_issuers_kps;
        for (int i = 0; i < num_other_issuers; i++) {
            other_issuers_kps.push_back(generateKeyPair(num_messages, &pfc, G2_gen));
        }
        
        cout << "\n[2] 每个签发方针对哈希值 h 生成签名份额..." << endl;
        cout << "    签名形式：(h, h^{x_i + \\Sigma y_{i,j} * m_j})" << endl;
        
        vector<SigShare> all_shares;
        
        SigShare share_initiator = signShare(kp_initiator, messages, h, &pfc);
        all_shares.push_back(share_initiator);
        
        SigShare share_dm = signShare(kp_dm, messages, h, &pfc);
        all_shares.push_back(share_dm);
        
        for (int i = 0; i < num_other_issuers; i++) {
            all_shares.push_back(signShare(other_issuers_kps[i], messages, h, &pfc));
        }
        
        cout << "\n[3] 签名发起方收集并聚合所有签名份额..." << endl;
        SigShare aggregated_sig = aggregateSignatures(all_shares);
        cout << "  -> 聚合签名 (h, 相乘后的结果 S_agg) 生成完成。" << endl;
        
        cout << "\n[4] 签名发起方聚合所有参与者的公钥 apk..." << endl;
        vector<KeyPair> all_kps;
        all_kps.push_back(kp_initiator);     // 发起方
        all_kps.push_back(kp_dm);            // dm用户
        for (int i = 0; i < num_other_issuers; i++) {
            all_kps.push_back(other_issuers_kps[i]); // 其他签发方
        }
        AggregatedPK apk = aggregatePublicKeys(all_kps, num_messages);
        cout << "  -> 聚合公钥 apk (X_agg, Y_agg) 生成完成。" << endl;
        
        cout << "\n[5] 将聚合公钥 apk 与聚合签名返回给用户..." << endl;
        
        cout << "\n[6] 用户/验证方使用聚合公钥验证多签发方证书的合法性..." << endl;
        bool is_valid = verifySignature(apk, aggregated_sig, messages, G2_gen, &pfc);
        
        if (is_valid) {
            cout << "  -> 【验证成功！】该证书是由 1个发起方 + 1个dm关联方 + " 
                 << num_other_issuers << "个合作签发方 (共" 
                 << (2 + num_other_issuers) << "方) 共同协作签发生成的，验证通过，合法有效。" << endl;
        } else {
            cout << "  -> 【验证失败！】" << endl;
        }
        
        cout << "\n=== 可信第三方(TA)签名与随机化实验演示 ===" << endl;
        
        cout << "\n[7] TA生成密钥对..." << endl;
        TAKeyPair ta_kp = generateTAKeyPair(num_messages, &pfc, G1_gen);
        cout << "  -> TA 生成了公钥 (在G1上) 和私钥 (在Z_p上)" << endl;
        
        cout << "\n[8] TA对聚合公钥 apk 进行签名 (代数MAC)..." << endl;
        TASignature ta_sig = signAggregatedPK(ta_kp, apk, &pfc, G2_gen);
        cout << "  -> TA 签名 (R, S) 生成完毕！(都在G2上)" << endl;
        
        cout << "\n[9] 用户进行凭证的随机化(盲化)以便于出示..." << endl;
        RandomizedCredential rand_cred = randomizeCredential(apk, ta_sig, &pfc);
        cout << "  -> 用户生成了全新的、数学上不可被链接的盲化凭证 (apk'_x, apk'_i, R', S')" << endl;
        
        cout << "\n=== 验证者 NIZK 身份自证演示 ===" << endl;
        
        cout << "\n[10] 验证者建立自己的密钥对 (用于接受用户出示凭证)..." << endl;
        VerifierKeyPair verifier_kp = generateVerifierKeyPair(&pfc, G2_gen);
        string verifier_id = "Verifier-001";
        cout << "  -> 验证者 " << verifier_id << " 生成了公私钥对 (G2之上)。" << endl;
        
        cout << "\n[11] 验证者向用户发起身份证明 (NIZK PoK)..." << endl;
        NIZKProof nizk_proof = generateNIZKProof(verifier_id, verifier_kp, &pfc, G2_gen);
        cout << "  -> 验证者生成了非交互式零知识证明 (c, z) 发送给用户。" << endl;
        
        cout << "\n[12] 用户校验验证者的真实身份..." << endl;
        bool nizk_valid = verifyNIZKProof(verifier_id, verifier_kp.pk_V, nizk_proof, &pfc, G2_gen);
        if (nizk_valid) {
            cout << "  -> 【验证者 NIZK 校验成功！】用户确认对方是真实的 " << verifier_id << "，拥有对应的私钥。" << endl;
            cout << "  -> 用户同意将盲化后的证书出示给该验证者..." << endl;
        } else {
            cout << "  -> 【验证者 NIZK 校验失败！】用户拒绝出示凭证！" << endl;
            return -1; // 终止执行
        }

        cout << "\n[13] 第三方验证者验证盲化后的凭证..." << endl;
        bool ta_verify_valid = verifyRandomizedCredential(ta_kp.pk, rand_cred, &pfc, G1_gen);
        if (ta_verify_valid) {
            cout << "  -> 【TA签名盲化验证成功！】验证者仅通过一次验证等式，确定了凭证来自合法的TA并属于合法用户。" << endl;
        } else {
            cout << "  -> 【TA签名盲化验证失败！】" << endl;
        }
        
        cout << "\n=== 第三阶段：匿名出示与 OR-Proof ===" << endl;
        
        cout << "\n[14] 用户生成自己的临时密钥对以参与身份证明..." << endl;
        Big sk_U;
        pfc.random(sk_U);
        G2 pk_U = pfc.mult(G2_gen, sk_U);
        cout << "  -> 用户生成了参与 OR-Proof 的临时公钥 pk_U。" << endl;

        cout << "\n[15] 用户基于已有的多重PS凭证生成 OR-Proof..." << endl;
        PresentationPayload or_payload = generatePresentationPayload(apk, aggregated_sig, messages, pk_U, verifier_kp.pk_V, &pfc, G1_gen, G2_gen);
        cout << "  -> 用户生成了包括 c_left, T_left 乃至盲化后凭证的大礼包发送给验证者。" << endl;
        
        cout << "\n[16] 验证者验证 OR-Proof 及盲化凭证..." << endl;
        bool or_proof_valid = verifyORProof(or_payload, &pfc, G1_gen, G2_gen);
        if (or_proof_valid) {
            cout << "  -> 【OR-Proof 验证成功！】验证者确认了哈希分割一致、Right侧合规且Left侧配对无误。" << endl;
            cout << "  -> 整个协议执行圆满成功！" << endl;
        } else {
            cout << "  -> 【OR-Proof 验证失败！】存在数据篡改或对应不符合的情况。" << endl;
        }
        
        cout << "\n=== 第四阶段：验证者展示可否认性 (伪造 OR-Proof) ===" << endl;
        
        cout << "\n[17] 验证者利用自己的私钥伪造一个一模一样的展示大礼包..." << endl;
        PresentationPayload faked_payload = simulatePresentationPayloadByVerifier(verifier_kp, pk_U, messages, &pfc, G1_gen, G2_gen);
        cout << "  -> 验证者反转逻辑：凭空捏造盲化凭证 (Left侧伪造) + 真实出示私钥 (Right侧真实)。" << endl;
        
        cout << "\n[18] 第三方 (如法官) 验证该伪造的大礼包..." << endl;
        bool fake_proof_valid = verifyORProof(faked_payload, &pfc, G1_gen, G2_gen);
        if (fake_proof_valid) {
            cout << "  -> 【伪造证明验证成功！】" << endl;
            cout << "     因为验证者完全有能力毫无破绽地伪造出合法的展示记录，第三方无法确信该记录究竟是用户出示的，还是验证者自己捏造的。" << endl;
            cout << "     这赋予了用户绝对的【可否认性】！" << endl;
        } else {
            cout << "  -> 【伪造证明验证失败！】代码实现有误。" << endl;
        }
    }
    
    return 0;
}
