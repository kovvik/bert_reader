#!/usr/bin/env python3
# usage: bert_reader.py [-h] directory
#
# Decodes ACPI BERT tables and BERT Data Table
#
# positional arguments:
#   directory   acpi tables location
#
# optional arguments:
#   -h, --help  show this help message and exit
#

import argparse
import os
import glob
import sys
from tables import Bert, Hest, GenericErrorStatusBlock


def main(args):
    '''
    Main function.
    '''
    # Exit if location is not a valid dir
    if not os.path.isdir(args.acpi_location):
        print('ERROR: Not a valid directory')
        parser.print_help()
        sys.exit(1)
    # Find all BERT files
    bert_files = glob.glob(args.acpi_location + '/BERT*')
    if len(bert_files) > 0:
        # Iterate through BERT Table files
        for bert_file in bert_files:
            bert_table = Bert(bert_file)
            bert_table.print_data()
    else:
        print(f'ERROR: No BERT file in {args.acpi_location}')
        parser.print_help()
        sys.exit(1)
    # Read HEST file
    try:
        hest_table = Hest(args.acpi_location + '/HEST')
        hest_table.print_data()
    except:
        print(f'ERROR: No HEST file in {args.acpi_location}')
    # Read BERT data file
    generic_error_status_block = GenericErrorStatusBlock(
        os.path.join(args.acpi_location, 'data', 'BERT')
    )
    generic_error_status_block.print_data()

if __name__ == "__main__":
    # Parsing args
    parser = argparse.ArgumentParser(
        description='Decodes ACPI BERT tables and BERT Data Table'
    )
    parser.add_argument('acpi_location', metavar='directory', type=str,
                    help='acpi tables location')
    main(parser.parse_args())
