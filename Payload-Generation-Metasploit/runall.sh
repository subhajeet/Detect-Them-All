#!/bin/bash
sudo ./23.sh  #x86/alpha_mixed
sudo ./24.sh  #x86/alpha_upper
sudo ./25.sh  #x86/avoid_underscore_tolower
sudo ./26.sh  #x86/avoid_utf8_tolower
sudo ./27.sh  #x86/bloxor
sudo ./29.sh  #x86/call4_dword_xor
sudo ./30.sh  #x86/context_cpuid
sudo ./31.sh   #x86/context_stat
sudo ./32.sh   #x86/context_time
sudo ./33.sh   #x86/countdown
sudo ./34.sh   #x86/fnstenv_mov
sudo ./35.sh   #x86/jmp_call_additive
sudo ./36.sh   #x86/jmp_call_additive
sudo ./38.sh   #x86/opt_sub 
sudo ./39.sh   #x86/opt_sub 
sudo ./40.sh   #x86/shikata_ga_nai
sudo ./41.sh   #x86/single_static_bit
sudo ./42.sh   #x86/unicode_mixed
sudo ./43.sh   #x86/unicode_upper 
sudo ./44.sh   #x86/xor_dynamic
file * | grep ".dll" | wc -l  #Gives count of files with .dll extension
echo "Payload Generation Complete..." #Just a message


