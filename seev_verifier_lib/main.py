import json

import itertools
from functools import reduce
from pathlib import Path
from typing import Tuple


from seev_verifier_lib.verifier_lib import verify_signature, load_verify_signature, load_vote_proof, vote_proof, \
											load_ballot_proof, ballots_proof, load_tally_data, tally_check


def main():
	# json_location: Path = Path("reference_jsons/from_seev/response_1.json")
	# json_location: Path = Path("reference_jsons/from_seev/persisted_h_tally_2_contest_3_1abtain_3cancels_formated.json")
	# json_location: Path = Path("reference_jsons/from_seev/no_g_random_unformated.json")
	json_location: Path = Path("reference_jsons/from_seev/weighted_voting_1vote_formated.json")

	json_p: Path = Path(__file__).absolute().parent.parent / json_location

	with open(json_p, "r") as fin:
		data_raw = json.load(fin)

	# load the data and format them
	data = load_verify_signature(data_raw);	data = zip(*data[:2], itertools.repeat(data[-1]))
	res_signature: Tuple[bool, ...] = tuple(verify_signature(*d) for d in data)

	data = load_vote_proof(data_raw);	data = zip(*data)
	res_vote_proof: Tuple[bool, ...] = tuple(vote_proof(*d) for d in data)

	data = load_ballot_proof(data_raw);	data = zip(*data)
	res_ballot_proof: Tuple[bool, ...] = tuple(ballots_proof(*d) for d in data)

	data = load_tally_data(data_raw);	data = zip(*data)
	res_tally_proof: Tuple[bool, ...] = tuple(tally_check(*d) for d in data)

	print("SIGNATURE", res_signature)
	assert reduce(lambda x, y: x and y, res_signature) == True

	print("PROOF_VOTE", res_vote_proof)
	# assert reduce(lambda x, y: x and y, res_vote_proof) == True

	print("PROOF_BALLOT", res_ballot_proof)
	# assert reduce(lambda x, y: x and y, res_ballot_proof) == True
	#
	# print("PROOF_TALLY", res_tally_proof)


# assert reduce(lambda x, y: x and y, res_ballot_proof) == True

if __name__ == "__main__":
	main()