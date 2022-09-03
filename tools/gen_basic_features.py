import os
import chardet
import argparse
import re
import csv
import hashlib
import math
from inspect import ismethod
from collections import Counter
'''
Simple script to create a feature csv from a PowerShell corpus. Checkout the readme to see what features are extracted from corups. 

'''

def get_all_features(mf):
    for name in dir(mf):
        attribute = getattr(mf, name)
        if ismethod(attribute):
            try:
                attribute()
            except TypeError:
                pass
    return mf

def eta(data, unit='natural'):
    base = {
        'shannon' : 2.,
        'natural' : math.exp(1),
        'hartley' : 10.
    }
    if len(data) <= 1:
        return 0
    counts = Counter()
    for d in data:
        counts[d] += 1
    ent = 0
    probs = [float(c) / len(data) for c in counts.values()]
    for p in probs:
        if p > 0.:
            ent -= p * math.log(p, base[unit])
    return ent

class MyFeatures():
    def __init__(self, blob, infile):
        self.blob = blob
        self.blob_str = str(self.blob, 'UTF-8', 'ignore')
        self.feature_name_list = ['sha1', 'fpath', 'vt_harmless', 'vt_undetected', 'vt_malicious', 'vt_suspicious', 'avclass_name', 'is_obf', 'obf_name', \
            'char_hash_count', 'char_paren_count', 'char_brack_count', 'char_brace_count', 'char_bkslash_count', 'char_fwslash_count', 'char_dollar_count', \
            'char_squote_count', 'char_dquote_count', 'char_bktick_count', 'char_colon_count', 'char_scolon_count', 'char_star_count', 'char_minus_count', \
            'char_plus_count', 'char_percent_count', 'char_carrot_count', 'char_comma_count', 'char_period_count', 'char_glthan_count', 'char_num_count', \
            'char_ucase_count', 'char_lcase_count', 'char_eq_count', 'char_space_count', 'char_pipe_count', 'char_uscore_count', 'char_amp_count', \
            'char_excl_count', \
            'doc_char_count', 'doc_avg_line_len', 'doc_min_line_len', 'doc_max_line_len', 'doc_line_count', 'doc_mcomment_count', \
            'doc_entropy']

        self.dtypes = ['bool', 'char', 'int', 'long', 'float', 'single', 'double', 'decimal']
        for i in range(0,len(self.dtypes)):
            feature_name = 'doc_dtype_' + self.dtypes[i] + '_word_count'
            self.feature_name_list.append(feature_name)

        self.keywords = ['begin', 'break', 'catch', 'class', 'continue', 'data', 'define', 'do', 'dynamicparam', 'else', 'elseif', 'end', 'enum', \
            'exit', 'filter', 'finally', 'foreach', 'from', 'function', 'hidden', 'if', 'in', 'param', 'process', 'return', 'static', 'switch', \
            'throw', 'trap', 'try', 'until', 'using', 'var', 'while']
        for i in range(0, len(self.keywords)):
            feature_name = 'doc_keyword_' + self.keywords[i] + '_word_count'
            self.feature_name_list.append(feature_name)
        #todo: add these 
        self.comparison_operators = ['-eq', '-ieq', '-ceq', '-ne', '-ine', '-cne', '-gt', '-igt', '-cgt', '-ge', '-ige', '-cge', '-lt', '-ilt', \
            '-clt', '-le', '-ile', '-cle']
        self.matching_operators = ['-like', '-ilike', '-clike', '-notlike', '-inotlike', '-cnotlike', '-match', '-imatch', '-cmatch', '-notmatch', \
            '-inotmatch', '-cnotmatch']
        self.replacement_operators = ['-replace', '-ireplace', '-creplace']
        self.containment_operators = ['-contains', '-icontains', '-ccontains', '-notcontains', '-inotcontains', '-cnotcontains', '-in', '-notin']
        self.type_operators = ['-is', '-isnot']
        #end todo
        self.feature_dict = dict().fromkeys(self.feature_name_list)
        self.feature_dict['fpath'] = os.path.abspath(infile)
        self.feature_dict['doc_char_count'] = len(self.blob)
        self.feature_dict['sha1'] = hashlib.sha1(self.blob).hexdigest()

    def get_vt_hits(self):
        return
    def get_avclass_name(self):
        return
    def get_doc_avg_line_len(self):
        tmp = self.blob_str.split('\n')
        lens = [len(t) for t in tmp]
        avg = sum(lens) / len(lens)
        self.feature_dict['doc_avg_line_len'] = avg
        return
    def get_doc_min_line_len(self):
        tmp = self.blob_str.split('\n')
        lens = [len(t) for t in tmp]
        lens.sort()
        self.feature_dict['doc_min_line_len'] = lens[0]
        return
    def get_doc_max_line_len(self):
        lines = self.blob_str.split('\n')
        parts = [len(l) for l in lines]
        parts.sort()
        self.feature_dict['doc_max_line_len'] = parts[-1]
        return
    def get_doc_line_count(self):
        tmp = self.blob_str.split('\n')
        self.feature_dict['doc_line_count'] = len(tmp)
        return
    def get_doc_datatype_counts(self):
        for i in range(0,len(self.dtypes)):
            rexp = r'\s' + self.dtypes[i] + r'\s'
            feature_name = 'doc_dtype_' + self.dtypes[i] + '_word_count'
            self.feature_dict[feature_name] = len(re.findall(rexp, self.blob_str))
        return
    def get_doc_keyword_counts(self):
        for i in range(0, len(self.keywords)):
            rexp = r'\s' + self.keywords[i]
            feature_name = 'doc_keyword_' + self.keywords[i] + '_word_count'
            self.feature_dict[feature_name] = len(re.findall(rexp, self.blob_str))
        return
    # def get_doc_char_word_count(self):
    #     self.feature_dict['doc_char_word_count'] = len(re.findall(r'char', self.blob_str)) #fixme (maybe add space)
    #     return
    # def get_doc_int_word_count(self):
    #     self.feature_dict['doc_int_word_count'] = len(re.findall(r'int,', self.blob_str)) #fixme (maybe add space)
    #     return
    def get_doc_entropy(self):
        self.feature_dict['doc_entropy'] = eta(self.blob)
        return
    def get_char_hash_count(self):
        self.feature_dict['char_hash_count'] = len(re.findall(r'#', self.blob_str))
        return
    def get_char_paren_count(self):
        self.feature_dict['char_paren_count'] = len(re.findall(r'\(|\)', self.blob_str))
        return
    def get_char_brack_count(self):
        self.feature_dict['char_brack_count'] = len(re.findall(r'\[|\]', self.blob_str))
        return
    def get_char_brace_count(self):
        self.feature_dict['char_brace_count'] = len(re.findall(r'\{|\}', self.blob_str))
        return
    def get_char_bkslash_count(self):
        self.feature_dict['char_bkslash_count'] = len(re.findall(r'\\', self.blob_str))
        return
    def get_char_fwslash_count(self):
        self.feature_dict['char_fwslash_count'] = len(re.findall(r'\/', self.blob_str))
        return
    def get_char_dollar_count(self):
        self.feature_dict['char_dollar_count'] = len(re.findall(r'\$', self.blob_str))
        return
    def get_char_squote_count(self):
        self.feature_dict['char_squote_count'] = len(re.findall(r"\'", self.blob_str))
        return
    def get_char_dquote_count(self):
        self.feature_dict['char_dquote_count'] = len(re.findall(r'\"', self.blob_str))
        return
    def get_char_bktick_count(self):
        self.feature_dict['char_bktick_count'] = len(re.findall(r'\`', self.blob_str))
        return
    def get_char_colon_count(self):
        self.feature_dict['char_colon_count'] = len(re.findall(r'\:', self.blob_str))
        return
    def get_char_scolon_count(self):
        self.feature_dict['char_scolon_count'] = len(re.findall(r'\;', self.blob_str))
        return
    def get_char_star_count(self):
        self.feature_dict['char_star_count'] = len(re.findall(r'\*', self.blob_str))
        return
    def get_char_minus_count(self):
        self.feature_dict['char_minus_count'] = len(re.findall(r'\-', self.blob_str))
        return
    def get_char_plus_count(self):
        self.feature_dict['char_plus_count'] = len(re.findall(r'\+', self.blob_str))
        return
    def get_char_percent_count(self):
        self.feature_dict['char_percent_count'] = len(re.findall(r'\%', self.blob_str))
        return
    def get_char_carrot_count(self):
        self.feature_dict['char_carrot_count'] = len(re.findall(r'\^', self.blob_str))
        return
    def get_char_comma_count(self):
        self.feature_dict['char_comma_count'] = len(re.findall(r'\,', self.blob_str))
        return
    def get_char_period_count(self):
        self.feature_dict['char_period_count'] = len(re.findall(r'\.', self.blob_str))
        return
    def get_char_glthan_count(self):
        self.feature_dict['char_glthan_count'] = len(re.findall(r'\<|\>', self.blob_str))
        return
    def get_char_num_count(self):
        self.feature_dict['char_num_count'] = len(re.findall(r'[0-9]', self.blob_str))
        return
    def get_char_ucase_count(self):
        self.feature_dict['char_ucase_count'] = len(re.findall(r'[A-Z]', self.blob_str))
        return
    def get_char_lcase_count(self):
        self.feature_dict['char_lcase_count'] = len(re.findall(r'[a-z]', self.blob_str))
        return
    def get_char_eq_count(self):
        self.feature_dict['char_eq_count'] = len(re.findall(r'\=', self.blob_str))
        return
    def get_char_space_count(self):
        self.feature_dict['char_space_count'] = len(re.findall(r'\s', self.blob_str))
        return
    def get_char_pipe_count(self):
        self.feature_dict['char_pipe_count'] = len(re.findall(r'\|', self.blob_str))
        return
    def get_char_uscore_count(self):
        self.feature_dict['char_uscore_count'] = len(re.findall(r'\_', self.blob_str))
        return
    def get_char_amp_count(self):
        self.feature_dict['char_amp_count'] = len(re.findall(r'&', self.blob_str))
        return
    def is_obf(self):
        return
    def obf_name(self):
        return
    def get_doc_mcomment_count(self):
        self.feature_dict['doc_mcomment_count'] = len(re.findall(r'\<#|#\>', self.blob_str))
        return
    def get_char_excl_count(self):
        self.feature_dict['char_excl_count'] = len(re.findall(r'\!', self.blob_str))

def extract_file_features(infile, outfile, prepend = None, write_hdr = True):
    infile = infile.rstrip()
    if prepend:
        infile = prepend + infile
    #print('Processing file: "%s"' % infile)
    if os.path.exists(os.path.abspath(infile)) == False:
        return
        
    with open(os.path.abspath(infile), 'rb') as fd:
        data = fd.read()

    #print(data)
    mf = MyFeatures(data, infile)
    mf = get_all_features(mf)
    with open(outfile, 'a') as fd:
        writer = csv.DictWriter(fd, fieldnames=mf.feature_name_list)
        if write_hdr:
            writer.writeheader()
        writer.writerow(mf.feature_dict)
    return

def main(infile, outfile, prepend):
    with open(infile, 'rb') as fd:
        raw = fd.read(32) 
        encoding = chardet.detect(raw)['encoding']
    with open(infile, 'r', encoding=encoding, errors='ignore') as fd:
        sample_locs = fd.readlines()

    print('processing %d files...' % len(sample_locs))
    extract_file_features(sample_locs[0], outfile, prepend)
    for i in range(1, len(sample_locs)):
        extract_file_features(sample_locs[i], outfile, prepend, False)
        if i % 1000 == 0:
            print('completed: ', i, ' of: ', len(sample_locs))
    print('done')
    return

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('-i', '--in', required=True, help='Read paths from file and collect features...')
    ap.add_argument('-o', '--out', required=True, help='Output file')
    ap.add_argument('-p', '--prepend', required=False, help='Prepend constant value (drive letter or relative path) to beginning of all file paths from [file] argument')
    ap.add_argument('-c', '--clear', required=False, action='store_true', help='Clear output file if present')
    args = vars(ap.parse_args())
    if args['clear']:
        if os.path.isfile(args['out']):
            os.remove(args['out'])
    if args['in'] and args['out']:
        main(args['in'], args['out'], args['prepend'])