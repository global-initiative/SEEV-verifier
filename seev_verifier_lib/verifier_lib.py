import base64
import hashlib
import json
from functools import reduce
from types import NoneType
from typing import Tuple, List, cast, Dict, Any, Type, Optional, Union

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
		# state 0 receipt have just been created and not acted upon
		# they do not have any option selected (let alone confirmed)
		if ballot_receipt["state"] == 0: continue

		s_one = ballot_receipt["stage_one"]
		# justified by core.serializers.serialization_utils.serialized_data_to_message
		stage_one_data: bytes = json.dumps(s_one["stage_one_data"]).encode('utf-8')
		# justified by test.state_analysis.serialized_data_checks.check_bulletin_board_stage_one_serialization
		stage_on_signature: bytes = base64.b64decode(s_one["stage_one_signature"])

		stage_one_datas.append(stage_one_data); stage_on_signatures.append(stage_on_signature)
		# yield stage_one_data, stage_on_signature, public_key

	return stage_one_datas, stage_on_signatures, public_key

# signature justified by libs.cryptography.dre_ip.ballot_generator.BallotGenerator.generate_vote_cryptography
# that feed from libs.cryptography.dre_ip.proofs.OneOfNZKP
def verify_audited_ballots(g_1: EccPoint, g_2: EccPoint, r: Integer, v: Integer, R: EccPoint, Z: EccPoint) -> bool:
	Z_prime = g_1*((r+v) % Nist256.order)
	R_prime = g_2*(r  % Nist256.order)

	if Z_prime != Z or R_prime != R: 	return False
	else: 								return True


def load_verify_audited_ballots(data: Dict[str, Any]) -> Tuple[List[EccPoint], List[EccPoint], List[Integer], List[Integer],
											List[Integer], List[Integer], List[EccPoint], List[EccPoint],
											List[EccPoint], List[EccPoint], List[EccPoint], List[EccPoint],
											List[int], List[int], List[int], List[int]]:

	g_1s: List[EccPoint] = list(); 	g_2s: List[EccPoint] = list()
	rs: List[Integer] = list(); 	vs: List[Integer] = list()
	R: List[EccPoint] = list(); 	Z: List[EccPoint] = list()
	import_pt_fct = EccPointSerialisationUtils.import_named_curve_ecc_point_from_string_public_key

	g_1: EccPoint = Nist256.get_generator(); g_2: EccPoint = import_pt_fct(data["election_context"]["unique_generator"])

	for ballot_receipt in data["ballot_set"]:
		if ballot_receipt["state"] != 3: continue  # only consider the audited ballots
		s_one = ballot_receipt["stage_one"]; s_one_data = s_one["stage_one_data"]
		s_two = ballot_receipt["stage_two"]; s_two_data = s_two["stage_two_data"]

		sort_option_ids = lambda s: sorted(s, key=lambda i:i["option_id"])

		for one_of_n_zkp, zkp_secrets in zip(sort_option_ids(s_one_data["one_of_n_zkps"]), sort_option_ids(s_two_data["zkp_secrets"])):
			if int(one_of_n_zkp["option_id"]) != int(zkp_secrets["option_id"]):  # this should not happen, but in case an option is missing, that will be raised
				raise ValueError("Missaligned option_ids between one_of_n_zkps and zkp_secrets, please contact your administrator")
			g_1s.append(g_1)
			g_2s.append(g_2)

			rs.append(Integer(zkp_secrets["random"]))
			vs.append(Integer(zkp_secrets["vote_flag"]))

			R.append(import_pt_fct(one_of_n_zkp["cyphertext_R"]))
			Z.append(import_pt_fct(one_of_n_zkp["cyphertext_Z"]))


	return g_1s, g_2s, rs, vs, R, Z


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


def vote_proof_list(r_ss: List[List[Integer]], d_ss: List[List[Integer]],
					R_s: List[EccPoint], Z_s:List[EccPoint],
					A_ss: List[List[EccPoint]], B_ss: List[List[EccPoint]],
					election_ids: List[int], ballot_ids: List[int],
					option_ids: List[int], weights: List[int],
					election_data: Dict[str, Union[int, EccPoint, NoneType]]) -> bool:
	ballot_valid: bool = True; total_vote_weight: int = 0; vote_instances: int = 0
	min_votes, max_votes = election_data["min_votes"], election_data["max_votes"]
	g_1, g_2 = election_data["g_1"], election_data["g_2"]
	for r_s, d_s, R, Z, A_s, B_s, election_id, ballot_id, option_id, weight in zip(r_ss, d_ss, R_s, Z_s, A_ss, B_ss, election_ids, ballot_ids, option_ids, weights):
		vote_valid, vote_weight = vote_proof_list_single(g_1, g_2, r_s, d_s, R, Z, A_s, B_s, election_id, ballot_id, option_id, weight, weight_scan=election_data["voting_type"] == 2)
		ballot_valid &= vote_valid
		total_vote_weight += vote_weight
		if vote_weight > 0: vote_instances+=1

	if ballot_valid is False: return False
	if election_data["voting_type"] == 0:  		# default FPTP
		if vote_instances != 1: print("BAD FPTP"); return False
	elif election_data["voting_type"] == 1:  	# weighted voting
		if vote_instances != 1: print(f"BAD WEIGHTED VOTING, {vote_instances}"); return False
	elif election_data["voting_type"] == 2:  	# split voting
		if total_vote_weight != weights[0]: print("BAD SPLIT VOTING"); return False 	# this is the weight of the ballot repeated multiple times
	elif election_data["voting_type"] == 3:  	# weighted approval voting
		if min_votes == max_votes == None: print(f"BAD APPROVAL_VOTING PARAMETERS [{min_votes};{max_votes}] parameters not set"); return False
		if vote_instances < min_votes or vote_instances > max_votes: print(f"BAD APPROVAL_VOTING VOTING {vote_instances} for limits [{min_votes};{max_votes}]"); return False

	return True


def vote_proof_list_single(g_1: EccPoint, g_2: EccPoint,
					r_s: List[Integer], d_s: List[Integer],
					R: EccPoint, Z:EccPoint,
					A_s: List[EccPoint], B_s: List[EccPoint],
					election_id: int, ballot_id: int,
					option_id: int, weight: int, weight_scan: bool=False) -> Tuple[bool, int]:
	"""

	:param g_1:
	:param g_2:
	:param r_s:
	:param d_s:
	:param R:
	:param Z:
	:param A_s:
	:param B_s:
	:param election_id:
	:param ballot_id:
	:param option_id:
	:param weight:
	:param weight_scan: check the cryptography for multiple weight values as the split voting enables
						the voting power to be spread across the options
	:return:
	"""

	# public key validation
	if validate_public_key(R) is False or validate_public_key(Z) is False:
		return False, 0

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
											*[A.xy for A in A_s],
											*[B.xy for B in B_s]])
	# print("PRE_HASH", message)
	# print("HASH", hashlib.sha256(message.encode("utf-8")).digest().decode("utf-8"))
	challenge: bytes = Integer.from_bytes(hashlib.sha256(message.encode("utf-8")).digest(), 'big')

	# B_1_p = g_1*r_1 + Z*d_1
	# A_1_p = g_2*r_1 + R*d_1
	#
	# B_2_p = g_1*r_2 + (Z + -g_1)*d_2
	# A_2_p = g_2*r_2 + R*d_2

	# ok, so there is a hard codded permutation problem
	# the problem is that I really don't remember which one


	# right, so it appears that the reason why there are
	# 2 versions of each Bs is because depending on which B
	# is valid (B1 or B20, the identity of the base
	# (noted h is both cases in the pdf) is different
	# (from g_1 to g_2 -> from g to h according to the doc)
	# the same follows for the d and r used as an exponent.
	# This deviation is strange and might warrant a chat with
	# Feng.

	# No, it is not the base that is different, it is the d and r used
	# that has to do with how they are stored: you run through the rs and ds
	# as the option selected is not the same.
	# Meaning, should the first option be selected:
	# - the form of B1 is B_1_p_p
	# - the form of B2 is B_2_p
	# should the second option be selected, it becomes
	# - the form of B1 is B_1_p
	# - the form of B2 is B_2_p_p
	# So selection means that the short form is used...
	# That makes no sense, it has to be the other way around since the
	# long form contains the weight. [NEED REEVALUATION BUT USING LATER LOGIC]
	#
	# CUMULATIVE VOTING
	# So if I get that well, I need to check that for the cumulative voting
	# all options where a short form fails, start using the long form
	# with multiple weight - when all the weights have been found and
	# match the equalities, we can sum them up and check that they match
	# the weight.
	#
	# APPROVAL VOTING with weight
	# So this is pretty much the same as above, except that now I need to
	# get a fixed weight and count the number of instances of positive vote
	# (long form is True with the selected weight) and show that it is within
	# the provided range.

	# challenge verification
	sum_d: Integer = Integer(d_s[0])
	for i in d_s[1:]:	sum_d = sum_d + i
	if (sum_d % Nist256.order) != (challenge % Nist256.order): return False, 0  # the python code implements it with a modulus...

	# # through code reverse-engineering
	# B_1_p = g_1 * r_1 + (Z + -(g_1 * weight)) * d_1  # this one was a guess, there is nothing to indicate that Z should be (Z + -g_1). This is for when the option is selected
	# B_1_p_p = g_1 * r_1 + Z * d_1  # This is for when the option is not selected
	# A_1_p = g_2 * r_1 + R * d_1
	#
	# B_2_p = g_1 * r_2 + (Z + -(g_1 * weight)) * d_2
	# B_2_p_p = g_1 * r_2 + Z * d_2
	# A_2_p = g_2 * r_2 + R * d_2

	# A_p_s: List[EccPoint] = []  # Only one form exists for A_s
	# B_p_s: List[Tuple[EccPoint, EccPoint]] = []  # First position is the "voted form" long form, second is the short form
	# for i in range(len(A_s)): # compute all the alternative forms
	# 	A_p_s.append(g_2 * r_s[i] + R * d_s[i])
	# 	B_p_s.append((g_1 * r_s[i] + (Z + -(g_1 * weight)) * d_s[i],
	# 				  g_1 * r_s[i] + Z * d_s[i]))
	#
	# # verification
	# # need to scan for the position of the selected element, and then assert that all the rest is not selected
	# valid: bool = True; voted_option_selected: int = 0
	# nonvoted_option_selected: int = 0
	# for i, (A, B, A_p, (B_p_1, B_p_0)) in enumerate(zip(A_s, B_s, A_p_s, B_p_s)):  # consume all the alternative forms
	# 	# integrity
	# 	if A != A_p: print("A != A_p"); valid = False
	# 	if B_p_0 != B and B_p_1 != B: print("B_p_0 != B and B_p_1 != B"); valid = False
	# 	# selections
	# 	if B_p_0 == B:  nonvoted_option_selected += 1
	# 	if B_p_1 == B:	voted_option_selected += 1
	# 	if valid == False: break  # if something went wrong

	# verification
	# need to scan for the position of the selected element, and then assert that all the rest is not selected
	valid: bool = True; voted_option_selected: int = 0
	nonvoted_option_selected: int = 0; found_weight: int = weight
	for i, (A, B) in enumerate(zip(A_s, B_s)):  # consume all the alternative forms
		A_p = g_2 * r_s[i] + R * d_s[i]
		if A != A_p: print("A != A_p"); valid = False; break

		B_p_0 = g_1 * r_s[i] + Z * d_s[i]; B_p_1 = 0 # B_p_1 only computed if we think we have voted for this option
		if B_p_0 != B: # we seem to have voted for this option, computing the voted path
			if weight_scan is False:
				B_p_1 = g_1 * r_s[i] + (Z + -(g_1 * found_weight)) * d_s[i]
				if B_p_1 != B: print("B_p_0 != B and B_p_1 != B"); valid = False; break
			else:
				found_right_weight: bool = False
				for candidate_weight in range(1, weight+1):
					B_p_1 = g_1 * r_s[i] + (Z + -(g_1 * candidate_weight)) * d_s[i]
					if B_p_1 == B: found_right_weight = True; found_weight = candidate_weight; break # found the right one
				if found_right_weight is False: print("B_p_0 != B and not valid weight for B_p_1"); valid = False; break

		# integrity
		if B_p_0 != B and B_p_1 != B: print("B_p_0 != B and B_p_1 != B"); valid = False
		# selections
		if B_p_0 == B:  nonvoted_option_selected += 1
		if B_p_1 == B:	voted_option_selected += 1
		if valid == False: break  # if something went wrong
		
		
	# if A_1_p != A_1: 			return False
	# elif A_2_p != A_2: 			return False
	# # be consistent with the checks, p's with p's, p_p's with p_p's
	# if B_1_p != B_1 and B_1_p_p != B_1: 		return False
	# elif (B_2_p != B_2 and B_1_p == B_1) and (B_2_p_p != B_2 and B_1_p_p == B_1): 			return False

	if valid == False: return False, 0
	if voted_option_selected == nonvoted_option_selected: print("undecided vote"); return False, 0  # we either vote for an option or we do not.
	if not (voted_option_selected == len(A_s) or nonvoted_option_selected == len(A_s)): print(f"inconsistent vote {voted_option_selected}/{nonvoted_option_selected}"); return False, 0  # one of the two options has been selected

	print(f"inconsistent vote {voted_option_selected}/{nonvoted_option_selected} - {int(voted_option_selected == len(A_s))*found_weight}")
	return True, int(voted_option_selected == len(A_s))*found_weight

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

def load_vote_proof_list(data: Dict[str, Any]) -> Tuple[Tuple[List[List[List[Integer]]], List[List[List[Integer]]],
											List[List[EccPoint]], List[List[EccPoint]],
											List[List[List[EccPoint]]], List[List[List[EccPoint]]],
											List[List[int]], List[List[int]], List[List[int]], List[List[int]]],
											Dict[str, Union[int, EccPoint, NoneType]]]:

	g_1ss: List[List[EccPoint]] = list(); 	g_2ss: List[List[EccPoint]] = list()
	r_ss: List[List[List[Integer]]] = list(); d_ss: List[List[List[Integer]]] = list()
	R_ss: List[List[EccPoint]] = list(); 	Z_ss: List[List[EccPoint]] = list()
	A_ss: List[List[List[EccPoint]]] = list(); B_ss: List[List[List[EccPoint]]] = list()
	election_idss: List[List[int]] = list(); ballot_idss: List[List[int]] = list(); option_idss: List[List[int]] = list()
	weightss: List[List[int]] = list()
	
	import_pt_fct = EccPointSerialisationUtils.import_named_curve_ecc_point_from_string_public_key

	g_1: EccPoint = Nist256.get_generator(); g_2: EccPoint = import_pt_fct(data["election_context"]["unique_generator"])

	election_id: int = int(data["election_context"]["election_id"])
	election_data: Dict[str, Union[int, EccPoint, NoneType]] = {"election_id": election_id, "voting_type": int(data["election_context"]["voting_type"]),
													  "g_1": g_1, "g_2": g_2,
													  'min_votes': data["election_context"]["min_votes"] if 'min_votes' in data["election_context"] else None,
													  'max_votes': data["election_context"]["max_votes"] if 'max_votes' in data["election_context"] else None}
	for ballot_receipt in data["ballot_set"]:
		if ballot_receipt["state"]  == 0: continue  # ignore the ballot without options selected as those cannot be verified
		s_one = ballot_receipt["stage_one"]; s_one_data = s_one["stage_one_data"]; eq_zkp = s_one_data["equality_zkp"]
		ballot_id: int = int(ballot_receipt["ballot_id"]); weight: int = int(ballot_receipt["weight"])
		
		g_1s: List[EccPoint] = list(); 	g_2s: List[EccPoint] = list()
		r_s: List[List[Integer]] = list(); d_s: List[List[Integer]] = list()
		R_s: List[EccPoint] = list(); 	Z_s: List[EccPoint] = list()
		A_s: List[List[EccPoint]] = list(); B_s: List[List[EccPoint]] = list()
		election_ids: List[int] = list(); ballot_ids: List[int] = list(); option_ids: List[int] = list()
		weights: List[int] = list()

		for one_of_n_zkp in s_one_data["one_of_n_zkps"]:

			r_s.append([Integer(i) for i in one_of_n_zkp["result_r_i"]])
			d_s.append([Integer(i) for i in one_of_n_zkp["result_d_i"]])

			R_s.append(import_pt_fct(one_of_n_zkp["cyphertext_R"]))
			Z_s.append(import_pt_fct(one_of_n_zkp["cyphertext_Z"]))

			A_s.append([import_pt_fct(i) for i in one_of_n_zkp["commitments_A"]])
			B_s.append([import_pt_fct(i) for i in one_of_n_zkp["commitments_B"]])

			election_ids.append(election_id); ballot_ids.append(ballot_id); option_ids.append(int(one_of_n_zkp["option_id"]))

			weights.append(weight)

		g_1ss.append(g_1s); g_2ss.append(g_2s)
		r_ss.append(r_s); d_ss.append(d_s)
		R_ss.append(R_s); Z_ss.append(Z_s)
		A_ss.append(A_s); B_ss.append(B_s)
		election_idss.append(election_ids); ballot_idss.append(ballot_ids); option_idss.append(option_ids)
		weightss.append(weights)

	return (r_ss, d_ss, R_ss, Z_ss, A_ss, B_ss, election_idss, ballot_idss, option_idss, weightss), election_data

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
		# state 0 receipt have just been created and not acted upon
		# they do not have any option selected (let alone confirmed)
		if ballot_receipt["state"] == 0: continue

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

	# in the event where nobody voted in that election, the ballot set
	# is empty, so is the final tally along with any summations.
	if len(options_Rs) == 0 or len(options_Zs) == 0:
		return True

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


