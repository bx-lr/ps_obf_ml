import os
import argparse
import chardet
import random
import sys
import pandas as pd
'''
input file generation:
find test/PowerShellCorpus/* -type f | grep 'Technet\|PowerShellGallery' | grep 'psm1\|ps1'  | grep -v 'InvokeObfuscation' > ps_file_listing_technet_psgallery_no_obf.txt

then use gen_basic_features.py

this is used on the output of that script to do basic filtering, sampling, etc.
'''
def sample_random(infile, outfile, size):
    with open(infile, 'rb') as fd:
        raw = fd.read(32) 
        encoding = chardet.detect(raw)['encoding']
    with open(infile, 'r', encoding=encoding, errors='ignore') as fd:
        sample_locs = fd.readlines()
    size = int(size)
    items = random.sample(sample_locs, size)
    with open(outfile, 'w',  errors='ignore') as fd:
        fd.write(''.join(items))
    return 

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('-i', '--in', required=True, help='Input file to randomly select file paths from')
    ap.add_argument('-o', '--out', required=True, help='Output file to write results')
    ap.add_argument('-s', '--sample', required=False, help='Random sampling for size [int]')
    ap.add_argument('-c', '--clear', required=False, action='store_true', help='Clear output file if exists')
    ap.add_argument('-u', '--unique', required=False, action='store_true', help='Write unique rows to output')
    args = vars(ap.parse_args())
    if args['clear']:
        if os.path.isfile(args['out']):
            os.remove(args['out'])

    if args['unique']:
        df = pd.read_csv(args['in'])
        df.drop_duplicates('sha1', inplace=True)
        df.to_csv(args['out'], index=False)
        sys.exit(0)

    if args['sample']:
        df = pd.read_csv(args['in'])
        out_df = df.sample(n=int(args['sample']))
        out_df.to_csv(args['out'], index=False)
        sys.exit(0)
 

