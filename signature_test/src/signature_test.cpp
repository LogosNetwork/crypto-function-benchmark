#include <iostream>
#include "SignatureTestUtils.h"
//using namespace std;

//Zilliqa Schnorr
#include "libCrypto/MultiSig.h"

//openssl ECDSA
#include <string.h>
#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp192k1
#include <openssl/evp.h>
#include <openssl/sha.h>

//Nano EdDSA
#include <openssl/rand.h>
#include "ed25519-donna/ed25519.h"

#define NUM_NODES 				32
#define NUM_ROUNDS				1000
#define MULTI_SIG_MSG_SIZE		512
#define MAX_DIGEST_LEN			32

namespace CryptoPerfTest
{
int string_sizes[] = {128, 256, 512, 1024, 1024*2, 1024*4, 1024*8, 1024*16, 1024*32, 1024*64, 1024*128, 1024*256, 1024*512, 1024*1024};
//int string_sizes[] = {512};

void handleErrors(const char * s)
{
	cout << s << " error" << endl;
	exit(-1);
}

class EdDSA_Test
{
public:
	ed25519_secret_key sk;
	ed25519_public_key pk;

	vector<string> messages;
	int rounds;

	EdDSA_Test(int rounds)
	: sk()
	, messages()
	, rounds(rounds)
	{
	    if(1 != RAND_bytes(sk, sizeof(ed25519_secret_key)))
	    	handleErrors("RAND_bytes");

	    ed25519_publickey(sk, pk);
	}

	clock_t sign(int size)
	{
		SignatureTestUtils::getStrings(size, rounds, messages);

		clock_t t_start = clock();
		for(auto &msg : messages)
		{
			ed25519_signature sig;
			ed25519_sign((unsigned char *)msg.data(), msg.size(), sk, pk, sig);
		}
		return clock() - t_start;
	}

	clock_t verify(int size)
	{
		SignatureTestUtils::getStrings(size, rounds, messages);
		vector<ed25519_signature> sigs(rounds);

		for(int i = 0;i < rounds; ++i)
		{
			auto &msg = messages[i];
			ed25519_sign((unsigned char *)msg.data(), msg.size(), sk, pk, sigs[i]);
		}

		clock_t t_start = clock();
		for(int i = 0;i < rounds; ++i)
		{
			auto &msg = messages[i];
			auto &sig = sigs[i];
			ed25519_sign_open((unsigned char *)msg.data(), msg.size(), pk, sig);
		}
		return clock() - t_start;
	}
};

///////////////////////////////////////////////////////////////////////////////////
class ECDSA_Test
{
public:
	EC_KEY *eckey;

	vector<string> messages;
	int rounds;

	ECDSA_Test(int rounds)
	: eckey(EC_KEY_new())
	, messages()
	, rounds(rounds)
	{
		if (NULL == eckey)
			handleErrors("Failed to create new EC Key");

		EC_GROUP *ecgroup= EC_GROUP_new_by_curve_name(NID_secp256k1);
		if (NULL == ecgroup)
			handleErrors("EC_GROUP_new_by_curve_name error");

		if(1 != EC_KEY_set_group(eckey,ecgroup))
			handleErrors("EC_KEY_set_group error");

		if(1 != EC_KEY_generate_key(eckey))
			handleErrors("EC_KEY_generate_key error");
	}

	ECDSA_SIG * sign(string & msg)
	{
		unsigned char digest[MAX_DIGEST_LEN];
		SHA256((unsigned char *)msg.data(), msg.size(), digest);
		ECDSA_SIG *signature = ECDSA_do_sign(digest, MAX_DIGEST_LEN, eckey);
		if (NULL == signature)
			handleErrors("ECDSA_do_sign error");
		return signature;
	}

	clock_t sign(int size)
	{

		SignatureTestUtils::getStrings(size, rounds, messages);

		clock_t t_start = clock();
		for(auto &msg : messages)
		{
			ECDSA_SIG * sig = sign(msg);
			ECDSA_SIG_free(sig);
		}
		return clock() - t_start;
	}

	void verify(string &msg, ECDSA_SIG *signature)
	{
		unsigned char digest[MAX_DIGEST_LEN];
		SHA256((unsigned char *)msg.data(), msg.size(), digest);

		if (1 != ECDSA_do_verify(digest, MAX_DIGEST_LEN, signature, eckey))
			handleErrors("ECDSA_do_verify");
	}

	clock_t verify(int size)
	{
		SignatureTestUtils::getStrings(size, rounds, messages);
		vector<ECDSA_SIG *> sigs;

		for(int i = 0;i < rounds; ++i)
		{
			auto &msg = messages[i];
			sigs.push_back(sign(msg));
		}

		clock_t t_start = clock();
		for(int i = 0;i < rounds; ++i)
		{
			auto &msg = messages[i];
			auto &sig = sigs[i];
			verify(msg, sig);
		}
		return clock() - t_start;
	}
};

struct EC_Schnorr_multi_sig
{
	int num_nodes;
	vector<PrivKey> &skeys;
	vector<PubKey> &pkeys;
	shared_ptr<PubKey> apk;

	vector<unsigned char> & message;

	vector<CommitSecret> commitSecrets;
	vector<CommitPoint> commitPoints;
	vector<Response> responses;

	shared_ptr<CommitPoint> acp;
	shared_ptr<Response> arsp;
	shared_ptr<Signature> asig;

	shared_ptr<Challenge> challenge;

	EC_Schnorr_multi_sig(int nodes, vector<PrivKey> &skeys, vector<PubKey> &pkeys, shared_ptr<PubKey> apk, vector<unsigned char> & msg)
	: num_nodes(nodes)
	, skeys(skeys)
	, pkeys(pkeys)
	, apk(apk)
	, message(msg)
	, commitSecrets()
	, commitPoints()
	, responses()
	, acp()
	, arsp()
	, asig()
	, challenge()
	{

	}
	void genCommitPoints()
	{
		commitSecrets.resize(num_nodes);
		for(int i=0; i<num_nodes;++i)
		{
			commitPoints.push_back(CommitPoint(commitSecrets[i]));
			if(!commitPoints[i].Initialized())
				handleErrors("!commitPoints[i].Initialized");
		}
	}

	void aggregateCommits()
	{
		acp = MultiSig::AggregateCommits(commitPoints);
	}
	void genChallenge()
	{
		challenge = make_shared<Challenge>(Challenge(*acp, *apk, message, 0, message.size()));
	}

	void genResponse()
	{
		for(int i=0; i<num_nodes;++i)
		{
			responses.push_back(Response(commitSecrets[i], *challenge, skeys[i]));
			if(!responses[i].Initialized())
				handleErrors("!responses[i].Initialized()");
		}
	}

	void verifyResponse()
	{
		for(int i=0; i<num_nodes;++i)
		{
			if(!MultiSig::VerifyResponse(responses[i], *challenge, pkeys[i], commitPoints[i]))
				handleErrors("!VerifyResponse");
		}
	}

	void aggregateResponses()
	{
		arsp = MultiSig::AggregateResponses(responses);
	}

	void aggregateSign()
	{
		asig = MultiSig::AggregateSign(*challenge, *arsp);
	}

	void verifySig()
	{
		if(!Schnorr::GetInstance().Verify(message, *asig, *apk))
			handleErrors("schnorr.Verify");
	}
};

struct Multi_sig_times
{
	int rounds, num_nodes;
	clock_t agg_key, sign, agg_sig, agg_verify, individual_verify;

	Multi_sig_times(int rounds, int num_nodes, clock_t agg_key, clock_t sign, clock_t agg_sig, clock_t agg_verify, clock_t individual_verify)
	: rounds(rounds)
	, num_nodes(num_nodes)
	, agg_key(agg_key)
	, sign(sign)
	, agg_sig(agg_sig)
	, agg_verify(agg_verify)
	, individual_verify(individual_verify)
	{

	}
};

class EC_Schnorr_Multi_Test
{
public:
	int num_nodes;
	vector<PrivKey> skeys;
	vector<PubKey> pkeys;
	shared_ptr<PubKey> apk;

	int rounds;
	vector<vector<unsigned char> > messages;
	vector<EC_Schnorr_multi_sig> multi_sigs;

	EC_Schnorr_Multi_Test(int nodes, int rounds)
	: num_nodes(nodes)
	, skeys()
	, pkeys()
	, apk()
	, rounds(rounds)
	, messages()
	, multi_sigs()
	{
		num_nodes = nodes;
		skeys.resize(num_nodes);
		for(int i=0; i<num_nodes;++i)
		{
			if(!skeys[i].Initialized())
				handleErrors("!skeys[i].Initialized()");

			pkeys.push_back(PubKey(skeys[i]));

			if(!pkeys[i].Initialized())
				handleErrors("!pkeys[i].Initialized()");
		}
		apk = MultiSig::AggregatePubKeys(pkeys);
	}

	clock_t testPubkeyAgg()
	{
		clock_t t_start = clock();
		for(int i = 0; i < rounds; ++i)
		{
			auto apk_temp = MultiSig::AggregatePubKeys(pkeys);
		}
		return clock() - t_start;
	}

	Multi_sig_times test(int size)
	{
		SignatureTestUtils::getStrings(size, rounds, messages);
		clock_t t_start;

		for(auto &msg : messages)
		{
			multi_sigs.push_back(EC_Schnorr_multi_sig(num_nodes, skeys, pkeys, apk, msg));
		}

		t_start = clock();
		for(auto &msig : multi_sigs)
		{
			msig.genCommitPoints();
		}
		clock_t time_commitPoints = clock() - t_start;

		t_start = clock();
		for(auto &msig : multi_sigs)
		{
			msig.aggregateCommits();
			msig.genChallenge();
		}
		clock_t time_chall = clock() - t_start;

		t_start = clock();
		for(auto &msig : multi_sigs)
		{
			msig.genResponse();
		}
		clock_t time_rsp = clock() - t_start;

		t_start = clock();
		for(auto &msig : multi_sigs)
		{
			msig.verifyResponse();
		}
		clock_t time_v_rsp = clock() - t_start;

		t_start = clock();
		for(auto &msig : multi_sigs)
		{
			msig.aggregateResponses();
			msig.aggregateSign();
		}
		clock_t time_asig = clock() - t_start;

		t_start = clock();
		for(auto &msig : multi_sigs)
		{
			msig.verifySig();
		}
		clock_t time_verify = clock() - t_start;

		return Multi_sig_times(rounds, num_nodes, testPubkeyAgg(), time_commitPoints+time_rsp, time_chall+time_asig, time_verify, time_v_rsp);
	}
};

class EC_Schnorr_Test
{
public:
	PrivKey skey;
	PubKey pkey;

	vector<vector<unsigned char> > messages;
	int rounds;

	EC_Schnorr_Test(int rounds)
	: skey()
	, pkey(skey)
	, messages()
	, rounds(rounds)
	{
		if(!skey.Initialized())
			handleErrors("!skey.Initialized()");

		if(!pkey.Initialized())
			handleErrors("!pkey.Initialized()");
	}

	clock_t sign(int size)
	{
		SignatureTestUtils::getStrings(size, rounds, messages);

		clock_t t_start = clock();
		for(auto &msg : messages)
		{
			Signature sig;
			if(!Schnorr::GetInstance().Sign(msg, skey, pkey, sig))
			   	handleErrors("schnorr.Sign");
		}
		return clock() - t_start;
	}

	clock_t verify(int size)
	{
		SignatureTestUtils::getStrings(size, rounds, messages);

		vector<Signature> sigs(rounds);
		assert(sigs.size() == messages.size());

		for(int i = 0;i < rounds; ++i)
		{
			auto &msg = messages[i];
			auto &&sig = sigs[i];
			if(!Schnorr::GetInstance().Sign(msg, skey, pkey, sig))
			   	handleErrors("schnorr.Sign");
		}

		clock_t t_start = clock();
		for(int i = 0;i < rounds; ++i)
		{
			auto &msg = messages[i];
			auto &sig = sigs[i];
			if(!Schnorr::GetInstance().Verify(msg, sig, pkey))
			   	handleErrors("schnorr.Verify");
		}
		return clock() - t_start;
	}
};

}

int main( int argc , char * argv[] )
{
	{
		CryptoPerfTest::ECDSA_Test ecdsa(NUM_ROUNDS);
		for(auto size : CryptoPerfTest::string_sizes)
		{
			auto t = ecdsa.sign(size);
			cout << "ECDSA_sign: msg_size=" << size << " time(ms)=" << CryptoPerfTest::SignatureTestUtils::ticks2ms(t, NUM_ROUNDS) << endl;
			t = ecdsa.verify(size);
			cout << "ECDSA_verify: msg_size=" << size << " time(ms)=" << CryptoPerfTest::SignatureTestUtils::ticks2ms(t, NUM_ROUNDS) << endl;
		}
	}
	{
		CryptoPerfTest::EdDSA_Test eddsa(NUM_ROUNDS);
		for(auto size : CryptoPerfTest::string_sizes)
		{
			auto t = eddsa.sign(size);
			cout << "EdDSA_sign: msg_size=" << size << " time(ms)=" << CryptoPerfTest::SignatureTestUtils::ticks2ms(t, NUM_ROUNDS) << endl;
			t = eddsa.verify(size);
			cout << "EdDSA_verify: msg_size=" << size << " time(ms)=" << CryptoPerfTest::SignatureTestUtils::ticks2ms(t, NUM_ROUNDS) << endl;
		}
	}

	{
		CryptoPerfTest::EC_Schnorr_Test single_schnorr(NUM_ROUNDS);
		for(auto size : CryptoPerfTest::string_sizes)
		{
			auto t = single_schnorr.sign(size);
			cout << "Schnorr_sign: msg_size=" << size << " time(ms)=" << CryptoPerfTest::SignatureTestUtils::ticks2ms(t, NUM_ROUNDS) << endl;
			t = single_schnorr.verify(size);
			cout << "Schnorr_verify: msg_size=" << size << " time(ms)=" << CryptoPerfTest::SignatureTestUtils::ticks2ms(t, NUM_ROUNDS) << endl;
		}
	}

	{
		CryptoPerfTest::EC_Schnorr_Multi_Test multi_schnorr(NUM_NODES, NUM_ROUNDS);
		CryptoPerfTest::Multi_sig_times times = multi_schnorr.test(MULTI_SIG_MSG_SIZE);

		cout << "Multi_Schnorr: msg_size=" << MULTI_SIG_MSG_SIZE << " agg_pkey_time(ms)=" << CryptoPerfTest::SignatureTestUtils::ticks2ms(times.agg_key, NUM_ROUNDS) << endl;
		cout << "Multi_Schnorr: msg_size=" << MULTI_SIG_MSG_SIZE << " sign_time(ms)=" << CryptoPerfTest::SignatureTestUtils::ticks2ms(times.sign, NUM_ROUNDS) << endl;
		cout << "Multi_Schnorr: msg_size=" << MULTI_SIG_MSG_SIZE << " agg_sig_time(ms)=" << CryptoPerfTest::SignatureTestUtils::ticks2ms(times.agg_sig, NUM_ROUNDS) << endl;
		cout << "Multi_Schnorr: msg_size=" << MULTI_SIG_MSG_SIZE << " agg_verify_time(ms)=" << CryptoPerfTest::SignatureTestUtils::ticks2ms(times.agg_verify, NUM_ROUNDS) << endl;
		cout << "Multi_Schnorr: msg_size=" << MULTI_SIG_MSG_SIZE << " resp_verify_time(ms)=" << CryptoPerfTest::SignatureTestUtils::ticks2ms(times.individual_verify, NUM_ROUNDS) << endl;

	}
    cout << "done" << endl;
    return 0 ;
}
