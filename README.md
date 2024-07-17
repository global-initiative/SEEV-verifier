# SEEV-verifier

This repository contains the implementation of the SEEV DRE-IP algorithm verifier.

## Requirements
The current software has been tested on Ubuntu 20.04 using Python 3.10.13 and 3.10.14. We expect to be compatible with any modern flavour of Mac OS and Microsoft Windows.

The installation of the library supposes the presence of pipenv on the host machine that is used as the package manager for this project (see `Pipfile` file at the root of the project)

## Installation

Once you have the Python interpreter of your choice ready to be used, navigate to the root of this repository and run
```shell
pipenv install
```

The software should now have the necessary requirements installed.

## Use

The software is very straightforward to use. To verify an election's contest, download the associated bulletin board `json` file and use the following command
```shell
python -m seev_verifier_lib.main /absolute/or/relative/path/to/file/bulletin_board.json
```

The expected output should look something like this:
```log
Verification...
----------------------------------------------------------------------------------
        - SIGNATURE              (True, True, True, True)
        - VOTE                   (True, True, True, True, True, True, True, True)
        - BALLOT                 (True, True, True, True)
        - TALLY                  (True, True)
        - AUDITED BALLOTS        (True, True, True, True, True, True)
----------------------------------------------------------------------------------

The election has been successfully verified.
```

Or for an invalid election - here with an invalid signature:
```log
Verification...
----------------------------------------------------------------------------------
Invalid signature The signature is not authentic
        - SIGNATURE              (False, True)
        - VOTE                   (True, True, True, True, True, True)
        - BALLOT                 (True, True)
        - TALLY                  (True, True, True)
        - AUDITED BALLOTS        ()
----------------------------------------------------------------------------------

The election failed to pass the verification process.
```