# ps_obf_ml
Welcome to a simple project that will try to detect obfuscated PowerShell scripts. We're not going to be doing anything fancy like parsing an AST to do this (Revoke-Obfuscation). Also, were not trying to identify if scripts are malicious. Simply put, we only want to see if we can detect the presence of obfuscated content within a given PowerShell script. 

Basically, if the thing is obfuscated we should flag it.... Here goes!

# Data Source:
BEWARE THERE IS MALWARE IN IT!!!
```text
hxxps://aka\[.\]ms/PowerShellCorpus
```
Source file details: 

SHA1: 5920bb51bf3ed29e69e594d3b211af4c51dfdf84 

File name: PowerShellCorpus.zip

File size: 1342029170 bytes

PowerShellCorpus.zip contains 409876 PowerShell scripts collected in 2017 from GitHub, Technet, PowerShellGallery, and other sources. 

Scripts from the corpus are unlabled and in varying states good vs bad or obfuscated vs clean. 

The scripts were individually processed to obtain the features discussed below.

# Data Description:
As mentioned above, PowerShellCorpus.zip was processed to obtain a series of features with which we hope to identify the presence or absence of obfuscation through varying methods. The data set contains 87 features across 409876 observations. A brief description of each feature is provided below:

| Feature Name      | Description |
| ----------- | ----------- |
| SHA1      | SHA1 cryptographic hash of the input file       |
| fpath   | Fully qualified path to the input file        |
| vt_harmless   | No data, reserved for future use        |
| vt_undetected   | No data, reserved for future use        |
| vt_malicious   | No data, reserved for future use        |
| vt_suspicious   | No data, reserved for future use        |
| avclass_name   | No data, reserved for future use        |
| is_obf   | No data, reserved for future use        |
| obf_name   | No data, reserved for future use        |
| char_hash_count   | Count of the number of times the literal character '#' (0x23) was found in the file        |
| char_paren_count   | Count of the number of times the literal character '(' (0x28) and ')' (0x29) was found in the file        |
| char_brack_count   | Count of the number of times the literal character '[' (0x5B) and ']' (0x5D) was found in the file        |
| char_brace_count   | Count of the number of times the literal character '{' (0x7B and '}' (0x7D) was found in the file        |
| char_bkslash_count   | Count of the number of times the literal character '\' (0x5C) was found in the file        |
| char_fwslash_count   | Count of the number of times the literal character '/' (0x2F) was found in the file        |
| char_dollar_count   | Count of the number of times the literal character '$' (0x24) was found in the file        |
| char_squote_count   | Count of the number of times the literal character "'" (0x27) was found in the file        |
| char_dquote_count   | Count of the number of times the literal character '"' (0x22) was found in the file        |
| char_bktick_count   | Count of the number of times the literal character '`' (0x60) was found in the file        |
| char_colon_count   | Count of the number of times the literal character ':' (0x3A) was found in the file        |
| char_scolon_count   | Count of the number of times the literal character ';' (0x3B) was found in the file        |
| char_star_count   | Count of the number of times the literal character '*' (0x2A) was found in the file        |
| char_minus_count   | Count of the number of times the literal character '-' (0x2D) was found in the file        |
| char_plus_count   | Count of the number of times the literal character '+' (0x2B) was found in the file        |
| char_percent_count   | Count of the number of times the literal character '%' (0x25) was found in the file        |
| char_carrot_count   | Count of the number of times the literal character '^' (0x5E) was found in the file        |
| char_comma_count   | Count of the number of times the literal character ',' (0x2C) was found in the file        |
| char_period_count   | Count of the number of times the literal character '.' (0x2E) was found in the file        |
| char_glthan_count   | Count of the number of times the literal character '<' (0x3C) and '>' (0x3E) was found in the file        |
| char_num_count   | Count of the number of times numeric characters '0' (0x30) through '9' (0x39) were found in the file        |
| char_ucase_count   | Count of the number of times uppercase alphabetic characters 'A' (0x41) through 'Z' (0x5A) were found in the file        |
| char_lcase_count   | Count of the number of times uppercase alphabetic characters 'a' (0x61) through 'z' (0x7A) were found in the file        |
| char_eq_count   | Count of the number of times the literal character '=' (0x3D) was found in the file        |
| char_space_count   | Count of the number of times the literal character ' ' (0x20) was found in the file        |
| char_pipe_count   | Count of the number of times the literal character '\|' (0x7C) was found in the file        |
| char_uscore_count   | Count of the number of times the literal character '_' (0x5F) was found in the file        |
| char_amp_count   | Count of the number of times the literal character '&' (0x26) was found in the file        |
| char_excl_count   | Count of the number of times the literal character '!' (0x21) was found in the file        |
| doc_char_count   | Count of the number of characters in the file        |
| doc_avg_line_len   | Mean number of characters per line in the file        |
| doc_min_line_len   | Minimum number of characters per line in the file        |
| doc_max_line_len   | Maximum number of characters per line in the file        |
| doc_line_count   | Count of the number of lines in the file        |
| doc_mcomment_count   | Count of the number of multiline comment sequences in the file '<#' (0x3C 0x23) and '#>' (0x23 0x3E)       |
| doc_entropy   | Calculation of the Shannon entropy for the file       |
| doc_dtype_bool_word_count	    | Count of the number of times the word 'bool' is present in the file       |
| doc_dtype_char_word_count	    | Count of the number of times the word 'char' is present in the file       |
| doc_dtype_int_word_count	    | Count of the number of times the word 'int' is present in the file       |
| doc_dtype_long_word_count	    | Count of the number of times the word 'long' is present in the file       |
| doc_dtype_float_word_count	    | Count of the number of times the word 'float' is present in the file       |
| doc_dtype_single_word_count	    | Count of the number of times the word 'single' is present in the file       |
| doc_dtype_double_word_count	    | Count of the number of times the word 'double' is present in the file       |
| doc_dtype_decimal_word_count	    | Count of the number of times the word 'decimal' is present in the file       |
| doc_keyword_begin_word_count	    | Count of the number of times the word 'begin' is present in the file       |
| doc_keyword_break_word_count	    | Count of the number of times the word 'break' is present in the file       |
| doc_keyword_catch_word_count	    | Count of the number of times the word 'catch' is present in the file       |
| doc_keyword_class_word_count	    | Count of the number of times the word 'class' is present in the file       |
| doc_keyword_continue_word_count	    | Count of the number of times the word 'continue' is present in the file       |
| doc_keyword_data_word_count	    | Count of the number of times the word 'data' is present in the file       |
| doc_keyword_define_word_count	    | Count of the number of times the word 'define' is present in the file       |
| doc_keyword_do_word_count	    | Count of the number of times the word 'do' is present in the file       |
| doc_keyword_dynamicparam_word_count	    | Count of the number of times the word 'dynamicparam' is present in the file       |
| doc_keyword_else_word_count	    | Count of the number of times the word 'else' is present in the file       |
| doc_keyword_elseif_word_count	    | Count of the number of times the word 'elseif' is present in the file       |
| doc_keyword_end_word_count	    | Count of the number of times the word 'end' is present in the file       |
| doc_keyword_enum_word_count	    | Count of the number of times the word 'enum' is present in the file       |
| doc_keyword_exit_word_count	    | Count of the number of times the word 'exit' is present in the file       |
| doc_keyword_filter_word_count	    | Count of the number of times the word 'filter' is present in the file       |
| doc_keyword_finally_word_count	    | Count of the number of times the word 'finally' is present in the file       |
| doc_keyword_foreach_word_count	    | Count of the number of times the word 'foreach' is present in the file       |
| doc_keyword_from_word_count	    | Count of the number of times the word 'from' is present in the file       |
| doc_keyword_function_word_count	    | Count of the number of times the word 'function' is present in the file       |
| doc_keyword_hidden_word_count	    | Count of the number of times the word 'hidden' is present in the file       |
| doc_keyword_if_word_count	    | Count of the number of times the word 'if' is present in the file       |
| doc_keyword_in_word_count	    | Count of the number of times the word 'in' is present in the file       |
| doc_keyword_param_word_count	    | Count of the number of times the word 'param' is present in the file       |
| doc_keyword_process_word_count	    | Count of the number of times the word 'process' is present in the file       |
| doc_keyword_return_word_count	    | Count of the number of times the word 'return' is present in the file       |
| doc_keyword_static_word_count	    | Count of the number of times the word 'static' is present in the file       |
| doc_keyword_switch_word_count	    | Count of the number of times the word 'switch' is present in the file       |
| doc_keyword_throw_word_count	    | Count of the number of times the word 'throw' is present in the file       |
| doc_keyword_trap_word_count	    | Count of the number of times the word 'trap' is present in the file       |
| doc_keyword_try_word_count	    | Count of the number of times the word 'try' is present in the file       |
| doc_keyword_until_word_count	    | Count of the number of times the word 'until' is present in the file       |
| doc_keyword_using_word_count	    | Count of the number of times the word 'using' is present in the file       |
| doc_keyword_var_word_count	    | Count of the number of times the word 'var' is present in the file       |
| doc_keyword_while_word_count	    | Count of the number of times the word 'while' is present in the file       |


More information about the PowerShell language and its structure can be found at: 
https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_keywords?view=powershell-7.2


# todo: 
1. add features for comparison operators (https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comparison_operators?view=powershell-7.2)
```text
    comparison operators: (ALL TODO)
        '-eq', '-ieq', '-ceq' : equals
        '-ne', '-ine', '-cne' : not equals
        '-gt', '-igt', '-cgt' : greater than
        '-ge', '-ige', '-cge' : greater than or equal
        '-lt', '-ilt', '-clt' : less than
        '-le', '-ile', '-cle' : less than or equal
    matching operators: (ALL TODO)
        '-like', '-ilike', '-clike' : string matches wildcard pattern
        '-notlike', '-inotlike', '-cnotlike' : string does not match wildcard pattern
        '-match', '-imatch', '-cmatch' : string matches regex pattern
        '-notmatch', '-inotmatch', '-cnotmatch' : string does not match regex pattern
    replacement operators: (ALL TODO)
        '-replace', '-ireplace', '-creplace' : replaces strings matching a regex pattern
    containment operators: (ALL TODO)
        '-contains', '-icontains', '-ccontains' : collection contains a value
        '-notcontains', '-inotcontains', '-cnotcontains' : collection does not contain a value
        '-in' : value is in a collection
        '-notin' : value is not in a collection
    type operators: (ALL TODO)
        '-is' : both objects are the same type
        '-isnot' : the objects are not the same type
```

2. add 'obfuscation' features for labeled data (obfuscate the scripts with the frameworks below, reprocess files, update data set).
    - is obfuscated 0/1 <----- todo
    - obfuscator name <------ todo (script to generate obfuscated samples from)
```text    
        - https://github.com/3NC0D/Powershell-Obfuscator
        - https://github.com/loneferret/cheapObfuscator
        - https://github.com/JoelGMSec/Invoke-Stealth
        - https://github.com/gh0x0st/Invoke-PSObfuscation
        - https://github.com/danielbohannon/Invoke-Obfuscation
        - https://github.com/CBHue/PyFuscation
        - https://github.com/GhostPack/Invoke-Evasion
        - https://github.com/cwolff411/powerob
        - https://github.com/tokyoneon/Chimera
        - https://github.com/Flangvik/AMSI.fail
```