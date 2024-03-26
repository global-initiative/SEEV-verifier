import base64
import hashlib
import json
from functools import reduce
from typing import Tuple, List, cast, Dict, Any, Type

from Crypto.PublicKey.ECC import EccKey, EccPoint
from Crypto.Math.Numbers import Integer

from seev_cryptography.lib.ecc.curves.nist256 import Nist256
from seev_cryptography.lib.ecc.ecc_curve import EccCurve
from seev_cryptography.lib.utils.key_utils import EccKeySerialisationUtils, EddsaSignatureUtils, EccPointSerialisationUtils

def verify_signature(stage_one_data: bytes, stage_on_signature: bytes, public_key: EccKey) -> bool:
	try:
		EddsaSignatureUtils.verify(stage_one_data, stage_on_signature, public_key)
		return True
	except TypeError as te:
		raise TypeError() from te
	except ValueError as ve:
		print(f"Invalid signature {ve}")
		return False

def load_verify_signature(data: Dict[str, Any]) -> Tuple[List[bytes], List[bytes], EccKey]:


	# justified by core.serializers.serializer_fields.PublicEccKeySerializationField
	public_key: EccKey = EccKeySerialisationUtils.import_public_key_from_string(data["election_context"]["public_key"])

	stage_one_datas: List[bytes] = list(); stage_on_signatures: List[bytes] = list()
	for ballot_receipt in data["ballot_set"]:
		s_one = ballot_receipt["stage_one"]
		# justified by core.serializers.serialization_utils.serialized_data_to_message
		stage_one_data: bytes = json.dumps(s_one["stage_one_data"]).encode('utf-8')
		# justified by test.state_analysis.serialized_data_checks.check_bulletin_board_stage_one_serialization
		stage_on_signature: bytes = base64.b64decode(s_one["stage_one_signature"])

		stage_one_datas.append(stage_one_data); stage_on_signatures.append(stage_on_signature)
		# yield stage_one_data, stage_on_signature, public_key

	return stage_one_datas, stage_on_signatures, public_key


def validate_public_key(p: EccPoint, curve_type: Type[EccCurve] = Nist256) -> bool:
	"""
	Performs a public key validation on the provided ECCPoint.
	This assumes that the point has already been shown to be on the curve

	:param p: a point on the NIST-256 curve
	:param curve_type: the type of the curve the point is supposed to be on, defaults to NIST256
	:return: true of the point is valid, False otherwise
	"""
	if p.is_point_at_infinity(): return False
	# checking p*h != infinity; with h = cofactor (equivalent to p*n = infinity; with n = order)
	if curve_type is Nist256:			pass # for NIST 256, the cofactor is 1; checking p.is_point_at_infinity() already satisfies the current test
	else: 								raise ValueError("Unknown curve type")
	if p.x < 0 or p.x > (Nist256.prime - 1): return False
	if p.y < 0 or p.y > (Nist256.prime - 1): return False
	return True

def vote_proof(g_1: EccPoint, g_2: EccPoint,
			   r_1: Integer, r_2: Integer,
			   d_1: Integer, d_2: Integer,
			   R: EccPoint, Z:EccPoint,
			   A_1: EccPoint, A_2: EccPoint,
			   B_1: EccPoint, B_2:EccPoint,
			   election_id: int, ballot_id: int, option_id: int, weight: int):

	# public key validation
	if validate_public_key(R) is False or validate_public_key(Z) is False:
		return False

	# from libs.cryptography.dre_ip.ballot_generator.BallotGenerator.generate_vote_cryptography
	_context_info = ','.join([str(election_id), str(option_id), str(ballot_id)])  # yes the order is different than the parameters
	# from libs.cryptography.dre_ip.proofs.EqualityZKP
	# message: str = ','.join(str(i) for i in [_context_info,
	# 										*g_1.xy,*g_2.xy,
	# 										*R.xy, *Z.xy,
	# 										A_1.xy, A_2.xy,
	# 										B_1.xy, B_2.xy])
	
	message: str = ','.join(str(i) for i in [_context_info,  # This matches the python code's order
											*g_2.xy, *g_1.xy,
											*Z.xy, *R.xy,
											A_1.xy, A_2.xy,
											B_1.xy, B_2.xy])
	# print("PRE_HASH", message)
	# print("HASH", hashlib.sha256(message.encode("utf-8")).digest().decode("utf-8"))
	challenge: bytes = Integer.from_bytes(hashlib.sha256(message.encode("utf-8")).digest(), 'big')

	# B_1_p = g_1*r_1 + Z*d_1
	# A_1_p = g_2*r_1 + R*d_1
	#
	# B_2_p = g_1*r_2 + (Z + -g_1)*d_2
	# A_2_p = g_2*r_2 + R*d_2


	# through code reverse-engineering
	B_1_p = g_1 * r_1 + (Z + -(g_1*weight)) * d_1  	# this one was a guess, there is nothing to indicate that Z should be (Z + -g_1). This is for when the option is selected
	B_1_p_p = g_1 * r_1 + Z * d_1			# This is for when the option is not selected
	A_1_p = g_2 * r_1 + R * d_1

	B_2_p = g_1 * r_2 + (Z + -(g_1*weight)) * d_2
	B_2_p_p = g_1 * r_2 + Z * d_2
	A_2_p = g_2 * r_2 + R * d_2

	# print(int((d_1 + d_2) % Nist256.order == challenge % Nist256.order),challenge, (d_1 + d_2) % Nist256.order)
	# print(d_1, d_2)
	# print((challenge - d_2) % Nist256.order, (challenge - d_1) % Nist256.order)
	# print(A_1.xy, "\n", A_2.xy, "\n", B_1.xy, "\n", B_2.xy)
	# print("")
	# print(A_1_p.xy, "\n", A_2_p.xy, "\n", B_1_p.xy, "\n", B_2_p.xy)
	# print("--------------------------------------------------------------------------------------------")

	if (d_1 + d_2) % Nist256.order != challenge % Nist256.order: 	return False  # the python code implements it with a modulus...
	if A_1_p != A_1: 			return False
	elif A_2_p != A_2: 			return False
	# be consistent with the checks, p's with p's, p_p's with p_p's
	if B_1_p != B_1 and B_1_p_p != B_1: 		return False
	elif (B_2_p != B_2 and B_1_p == B_1) and (B_2_p_p != B_2 and B_1_p_p == B_1): 			return False

	return True

def load_vote_proof(data: Dict[str, Any]) -> Tuple[List[EccPoint], List[EccPoint], List[Integer], List[Integer],
											List[Integer], List[Integer], List[EccPoint], List[EccPoint],
											List[EccPoint], List[EccPoint], List[EccPoint], List[EccPoint],
											List[int], List[int], List[int], List[int]]:

	g_1s: List[EccPoint] = list(); 	g_2s: List[EccPoint] = list()
	r_1s: List[Integer] = list(); 	r_2s: List[Integer] = list()
	d_1s: List[Integer] = list(); 	d_2s: List[Integer] = list()  # that might not be the right d
	R: List[EccPoint] = list(); 	Z: List[EccPoint] = list()
	A_1s: List[EccPoint] = list(); 	A_2s: List[EccPoint] = list()
	B_1s: List[EccPoint] = list(); 	B_2s: List[EccPoint] = list()
	election_ids: List[int] = list(); ballot_ids: List[int] = list(); option_ids: List[int] = list()
	weights: List[int] = list()
	import_pt_fct = EccPointSerialisationUtils.import_named_curve_ecc_point_from_string_public_key

	g_1: EccPoint = Nist256.get_generator(); g_2: EccPoint = import_pt_fct(data["election_context"]["unique_generator"])

	election_id: int = int(data["election_context"]["election_id"])
	for ballot_receipt in data["ballot_set"]:
		s_one = ballot_receipt["stage_one"]; s_one_data = s_one["stage_one_data"]; eq_zkp = s_one_data["equality_zkp"]
		ballot_id: int = int(ballot_receipt["ballot_id"]); weight: int = int(ballot_receipt["weight"])

		for one_of_n_zkp in s_one_data["one_of_n_zkps"]:
			g_1s.append(g_1)
			g_2s.append(g_2)

			r_1s.append(Integer(one_of_n_zkp["result_r_i"][0]))
			r_2s.append(Integer(one_of_n_zkp["result_r_i"][1]))

			d_1s.append(Integer(one_of_n_zkp["result_d_i"][0]))
			d_2s.append(Integer(one_of_n_zkp["result_d_i"][1]))

			R.append(import_pt_fct(one_of_n_zkp["cyphertext_R"]))
			Z.append(import_pt_fct(one_of_n_zkp["cyphertext_Z"]))

			A_1s.append(import_pt_fct(one_of_n_zkp["commitments_A"][0]))
			A_2s.append(import_pt_fct(one_of_n_zkp["commitments_A"][1]))

			B_1s.append(import_pt_fct(one_of_n_zkp["commitments_B"][0]))
			B_2s.append(import_pt_fct(one_of_n_zkp["commitments_B"][1]))

			weights.append(weight)

			election_ids.append(election_id); ballot_ids.append(ballot_id); option_ids.append(int(one_of_n_zkp["option_id"]))

	return g_1s, g_2s, r_1s, r_2s, d_1s, d_2s, R, Z, A_1s, A_2s, B_1s, B_2s, election_ids, ballot_ids, option_ids, weights

def ballots_proof(g_1: EccPoint, g_2: EccPoint, Rs: List[EccPoint], Zs: List[EccPoint], result: int,
				  commitment_1: EccPoint, commitment_2: EccPoint, election_id: int, ballot_id: int, weight: int) -> bool:
	R_sum = reduce(lambda x, y: x + y, Rs[1:], Rs[0]); Z_sum = reduce(lambda x, y: x + y, Zs[1:], Zs[0])

	_context_info = ','.join([str(election_id), str(ballot_id)])
	message: str = ','.join(str(i) for i in [_context_info,  # This matches the python code's order
											 *g_1.xy, *g_2.xy,
											 *commitment_1.xy, *commitment_2.xy])

	c: int = cast(int, Integer.from_bytes(hashlib.sha256(message.encode("utf-8")).digest(), 'big'))

	X: EccPoint = Z_sum + -(g_1*weight)

	g1_r = g_1 * result;	g1_r_p = commitment_1 + -X*c
	g2_r = g_2 * result;	g2_r_p = commitment_2 + -R_sum*c
	if g1_r != g1_r_p: return False
	if g2_r != g2_r_p: return False

	return True

def load_ballot_proof(data: Dict[str, Any]) -> Tuple[List[EccPoint], List[EccPoint], List[List[EccPoint]], List[List[EccPoint]],
											List[Integer], List[EccPoint], List[EccPoint], List[int], List[int], List[int]]:

	g_1s: List[EccPoint] = list(); 		g_2s: List[EccPoint] = list()
	Rs: List[List[EccPoint]] = list(); 	Zs: List[List[EccPoint]] = list()
	election_ids: List[int] = list(); 	ballot_ids: List[int] = list()
	results: List[Integer] = list()
	commitment_1s: List[EccPoint] = list(); commitment_2s: List[EccPoint] = list()
	weights: List[int] = list()
	import_pt_fct = EccPointSerialisationUtils.import_named_curve_ecc_point_from_string_public_key

	g_1: EccPoint = Nist256.get_generator(); g_2: EccPoint = import_pt_fct(data["election_context"]["unique_generator"])

	election_id: int = int(data["election_context"]["election_id"])
	for ballot_receipt in data["ballot_set"]:
		s_one_data = ballot_receipt["stage_one"]["stage_one_data"]; eq_zkp = s_one_data["equality_zkp"]

		# This is g_1^s and g_2^s
		results.append(Integer(eq_zkp["result"]))
		commitment_1s.append(import_pt_fct(eq_zkp["commitment_1"]))
		commitment_2s.append(import_pt_fct(eq_zkp["commitment_2"]))

		election_ids.append(election_id); ballot_ids.append(int(ballot_receipt["ballot_id"]))
		g_1s.append(g_1); g_2s.append(g_2)

		weights.append(int(ballot_receipt["weight"]))

		Rs.append([]); Zs.append([])
		for one_of_n_zkp in s_one_data["one_of_n_zkps"]:
			Rs[-1].append(import_pt_fct(one_of_n_zkp["cyphertext_R"]))
			Zs[-1].append(import_pt_fct(one_of_n_zkp["cyphertext_Z"]))

	return g_1s, g_2s, Rs, Zs, results, commitment_1s, commitment_2s, election_ids, ballot_ids, weights

def tally_check(g_1: EccPoint, g_2: EccPoint, options_Rs: List[EccPoint], options_Zs: List[EccPoint],
		  options_tally: int, options_sum: int):
	Rs_sum = reduce(lambda x, y: x + y, options_Rs[1:], options_Rs[0]); Zs_sum = reduce(lambda x, y: x + y, options_Zs[1:], options_Zs[0])

	# the modulus operation seems to be required, save the following error appears: ValueError: Error 14 during scalar multiplication
	C_g_1: EccPoint = g_1*((options_tally+options_sum) % Nist256.order)
	C_g_2: EccPoint = g_2*options_sum

	if C_g_1 != Zs_sum:	return False
	if C_g_2 != Rs_sum: return False

	return True

def load_tally_data(data: Dict[str, Any]) -> Tuple[List[EccPoint], List[EccPoint], List[List[EccPoint]], List[List[EccPoint]], List[Integer], List[Integer]]:


	options_Rs: List[List[EccPoint]] 	= list()
	options_Zs: List[List[EccPoint]] 	= list()
	options_tally: List[Integer] 			= list()
	options_sums: List[Integer] 		= list()
	index_map: Dict[int, int]			= dict()
	g_1s: List[EccPoint] = list();	g_2s: List[EccPoint] = list()
	import_pt_fct = EccPointSerialisationUtils.import_named_curve_ecc_point_from_string_public_key

	g_1: EccPoint = Nist256.get_generator();	g_2: EccPoint = import_pt_fct(data["election_context"]["unique_generator"])

	for idx, opt_entry in enumerate(data["option_set"]):
		options_tally.append(Integer(opt_entry["tally"]))
		options_sums.append(Integer(opt_entry["sum"]))
		options_Rs.append([]); options_Zs.append([])
		g_1s.append(g_1); g_2s.append(g_2)
		index_map[int(opt_entry["id"])] = idx

	for ballot_receipt in data["ballot_set"]:
		if int(ballot_receipt["state"]) != 2: continue  # ignore the ballots that are not confirmed
		s_one_data = ballot_receipt["stage_one"]["stage_one_data"]

		for one_of_n_zkp in s_one_data["one_of_n_zkps"]:
			options_Rs[index_map[int(one_of_n_zkp["option_id"])]].append(import_pt_fct(one_of_n_zkp["cyphertext_R"]))
			options_Zs[index_map[int(one_of_n_zkp["option_id"])]].append(import_pt_fct(one_of_n_zkp["cyphertext_Z"]))

	return g_1s, g_2s, options_Rs, options_Zs, options_tally, options_sums


