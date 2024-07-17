import json

import itertools
from functools import reduce
from typing import Tuple, Callable
import os
import sys

from seev_verifier_lib.verifier_lib import verify_signature, load_verify_signature, load_vote_proof, vote_proof, \
	load_ballot_proof, ballots_proof, load_tally_data, tally_check, load_verify_audited_ballots, verify_audited_ballots


def verify(data_raw):
	"""
	Verifies the DRE-IP source bulletin board data provided.

	"""
	print("Verification...")
	print("----------------------------------------------------------------------------------")
	data = load_verify_signature(data_raw);	data = zip(*data[:2], itertools.repeat(data[-1]))
	res_signature: Tuple[bool, ...] = tuple(verify_signature(*d) for d in data)
	print("\t- SIGNATURE\t\t", res_signature)

	data = load_vote_proof(data_raw);	data = zip(*data)
	res_vote_proof: Tuple[bool, ...] = tuple(vote_proof(*d) for d in data)
	print("\t- VOTE\t\t\t", res_vote_proof)

	data = load_ballot_proof(data_raw);	data = zip(*data)
	res_ballot_proof: Tuple[bool, ...] = tuple(ballots_proof(*d) for d in data)
	print("\t- BALLOT\t\t", res_ballot_proof)

	data = load_tally_data(data_raw);	data = zip(*data)
	res_tally_proof: Tuple[bool, ...] = tuple(tally_check(*d) for d in data)
	print("\t- TALLY\t\t\t", res_tally_proof)
	
	data = load_verify_audited_ballots(data_raw);	data = zip(*data)
	res_audited_ballots: Tuple[bool, ...] = tuple(verify_audited_ballots(*d) for d in data)
	print("\t- AUDITED BALLOTS\t", res_audited_ballots)

	reduce_fct: Callable[[bool, bool], bool] = lambda x, y: (x is True) and (y is True)
	final_res_signature: bool = reduce(reduce_fct, res_signature, True)
	final_res_vote_proof: bool = reduce(reduce_fct, res_vote_proof, True)
	final_res_ballot_proof: bool = reduce(reduce_fct, res_ballot_proof, True)
	final_res_tally_proof: bool = reduce(reduce_fct, res_tally_proof, True)
	final_res_audited_ballots: bool = reduce(reduce_fct, res_audited_ballots, True)
	election_valid = final_res_signature and final_res_vote_proof and final_res_ballot_proof and final_res_tally_proof and final_res_audited_ballots

	print("----------------------------------------------------------------------------------\n")
	if election_valid is True:
		print("The election has been successfully verified.")
	else:
		print("The election failed to pass the verification process.")


def read_and_parse_file(file_path):
	"""
	Reads the content of the provided file and calls the parse function on it.

	:param file_path: Path to the file (can be absolute or relative).
	"""
	try:
		# Normalize the path to ensure compatibility across Unix, Linux, Windows, and MacOS
		normalized_path = os.path.normpath(file_path)

		# Open and read the file
		with open(normalized_path, 'r', encoding='utf-8') as fin:
			data_raw = json.load(fin)

			# Call the parse function on the content of the file
			verify(data_raw)
	except FileNotFoundError:
		print("Error: The file does not exist.")
	except Exception as e:
		print(f"An error occurred while attempting to load the file to verify: {e}")


if __name__ == "__main__":
	if len(sys.argv) < 2:
		print("Usage: python script.py <path_to_file>")
		print("<path_to_file> is either absolute or relative to the location of this file")
	else:
		# Get the file path from the command line argument
		file_path = sys.argv[1]

		# Call the function to read and parse the file
		read_and_parse_file(file_path)

