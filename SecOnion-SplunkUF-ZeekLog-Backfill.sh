#!/bin/bash

gunzip *.gz

cat x509.* >> /nsm/zeek/logs/current/x509.log
rm -f x509.*log

cat weird.* >> /nsm/zeek/logs/current/weird.log 
rm -f weird.*log

cat tds_sql_batch.* >> /nsm/zeek/logs/current/tds_sql_batch.log
rm -f tds_sql_batch.*log

cat tds_rpc.* >> /nsm/zeek/logs/current/tds_rpc.log
rm -f tds_rpc.*log

cat tds.* >> /nsm/zeek/logs/current/tds.log
rm -f tds.*log

cat syslog.* >> /nsm/zeek/logs/current/syslog.log
rm -f syslog.*log

cat ssl.* >> /nsm/zeek/logs/current/ssl.log
rm -f ssl.*log

cat ssh.* >> /nsm/zeek/logs/current/ssh.log
rm -f ssh.*log

cat software.* >> /nsm/zeek/logs/current/software.log
rm -f software.*log

cat socks.* >> /nsm/zeek/logs/current/socks.log
rm -f socks.*log

cat smtp.* >> /nsm/zeek/logs/current/smtp.log
rm -f smtp.*log

cat smb_mapping.* >> /nsm/zeek/logs/current/smb_mapping.log
rm -f smb_mapping.*log

cat smb_files.* >> /nsm/zeek/logs/current/smb_files.log
rm -f smb_files.*log

cat rfb.* >> /nsm/zeek/logs/current/rfb.log
rm -f rfb.*log

cat rdp.* >> /nsm/zeek/logs/current/rdp.log
rm -f rdp.*log

cat profinet_dce_rpc.* >> /nsm/zeek/logs/current/profinet_dce_rpc.log
rm -f profinet_dce_rpc.*log

cat profinet.* >> /nsm/zeek/logs/current/profinet.log
rm -f profinet.*log

cat pe.* >> /nsm/zeek/logs/current/pe.log
rm -f pe.*log

cat ntp.* >> /nsm/zeek/logs/current/ntp.log
rm -f ntp.*log

cat ntlm.* >> /nsm/zeek/logs/current/ntlm.log
rm -f ntlm.*log

cat notice.* >> /nsm/zeek/logs/current/notice.log
rm -f notice.*log

cat ldap_search.* >> /nsm/zeek/logs/current/ldap_search.log
rm -f ldap_search.*log

cat ldap.* >> /nsm/zeek/logs/current/ldap.log
rm -f ldap.*log

cat known_services.* >> /nsm/zeek/logs/current/known_services.log
rm -f known_services.*log

cat known_hosts.* >> /nsm/zeek/logs/current/known_hosts.log
rm -f known_hosts.*log

cat known_certs.* >> /nsm/zeek/logs/current/known_certs.log
rm -f known_certs.*log

cat kerberos.* >> /nsm/zeek/logs/current/kerberos.log
rm -f kerberos.*log

cat ipsec.* >> /nsm/zeek/logs/current/ipsec.log
rm -f ipsec.*log

cat http.* >> /nsm/zeek/logs/current/http.log
rm -f http.*log

cat files.* >> /nsm/zeek/logs/current/files.log
rm -f files.*log

cat ecat_arp_info.* >> /nsm/zeek/logs/current/ecat_arp_info.log
rm -f ecat_arp_info.*log

cat dpd.* >> /nsm/zeek/logs/current/dpd.log
rm -f dpd.*log

cat dns.* >> /nsm/zeek/logs/current/dns.log
rm -f dns.*log

cat dhcp.* >> /nsm/zeek/logs/current/dhcp.log
rm -f dhcp.*log

cat dce_rpc.* >> /nsm/zeek/logs/current/dce_rpc.log
rm -f dce_rpc.*log

cat conn-summary.* >> /nsm/zeek/logs/current/conn-summary.log
rm -f conn-summary.*log

cat conn.* >> /nsm/zeek/logs/current/conn.log
rm -f conn.*log

cat capture_loss.* >> /nsm/zeek/logs/current/capture_loss.log
rm -f capture_loss.*log

cat broker.* >> /nsm/zeek/logs/current/broker.log
rm -f broker.*log

cat analyzer.* >> /nsm/zeek/logs/current/analyzer.log
rm -f analyzer.*log

cat dnp3.* >> /nsm/zeek/logs/current/dnp3.log
rm -f dnp3.*log

cat ftp.* >> /nsm/zeek/logs/current/ftp.log
rm -f ftp.*log

cat modbus.* >> /nsm/zeek/logs/current/modbus.log
rm -f modbus.*log

cat modbus_register_change.* >> /nsm/zeek/logs/current/modbus_register_change.log
rm -f modbus_register_change.*log

cat mysql.* >> /nsm/zeek/logs/current/mysql.log
rm -f mysql.*log

cat postgresql.* >> /nsm/zeek/logs/current/postgresql.log
rm -f postgresql.*log

cat quic.* >> /nsm/zeek/logs/current/quic.log
rm -f quic.*log

cat radius.* >> /nsm/zeek/logs/current/radius.log
rm -f radius.*log

cat sip.* >> /nsm/zeek/logs/current/sip.log
rm -f sip.*log

cat smb_cmd.* >> /nsm/zeek/logs/current/smb_cmd.log
rm -f smb_cmd.*log

cat snmp.* >> /nsm/zeek/logs/current/irc.log
rm -f irc.*log

cat tunnel.* >> /nsm/zeek/logs/current/tunnel.log
rm -f tunnel.*log

cat oscp.* >> /nsm/zeek/logs/current/oscp.log
rm -f oscp.*log

cat netcontrol.* >> /nsm/zeek/logs/current/netcontrol.log
rm -f netcontrol.*log

cat netcontrol_drop.* >> /nsm/zeek/logs/current/netcontrol_drop.log
rm -f netcontrol_drop.*log

cat netcontrol_catch_release.* >> /nsm/zeek/logs/current/netcontrol_catch_release.log
rm -f netcontrol_catch_release.*log

cat openflow.* >> /nsm/zeek/logs/current/openflow.log
rm -f openflow.*log

cat intel.* >> /nsm/zeek/logs/current/intel.log
rm -f intel.*log

cat notice_alarm.* >> /nsm/zeek/logs/current/notice_alarm.log
rm -f notice_alarm.*log

cat signatures.* >> /nsm/zeek/logs/current/signatures.log
rm -f signatures.*log

cat traceroute.* >> /nsm/zeek/logs/current/traceroute.log
rm -f traceroute.*log

cat known_modbus.* >> /nsm/zeek/logs/current/known_modbus.log
rm -f known_modbus.*log

cat unknown_protocols.* >> /nsm/zeek/logs/current/unknown_protocols.log
rm -f unknown_protocols.*log

cat weird_stats.* >> /nsm/zeek/logs/current/weird_stats.log
rm -f weird_stats.*log

cat mqtt_connect.* >> /nsm/zeek/logs/current/mqtt_connect.log
rm -f mqtt_connect.*log

cat cluster.* >> /nsm/zeek/logs/current/cluster.log
rm -f cluster.*log

cat config.* >> /nsm/zeek/logs/current/config.log
rm -f config.*log

cat loaded_scripts.* >> /nsm/zeek/logs/current/loaded_scripts.log
rm -f loaded_scripts.*log

cat packet_filter.* >> /nsm/zeek/logs/current/packet_filter.log
rm -f packet_filter.*log

cat print.* >> /nsm/zeek/logs/current/print.log
rm -f print.*log

cat prof.* >> /nsm/zeek/logs/current/prof.log
rm -f prof.*log

cat reporter.* >> /nsm/zeek/logs/current/reporter.log
rm -f reporter.*log

cat stats.* >> /nsm/zeek/logs/current/stats.log
rm -f stats.*log

cat stderr.* >> /nsm/zeek/logs/current/stderr.log
rm -f stderr.*log

cat stdout.* >> /nsm/zeek/logs/current/stdout.log
rm -f stdout.*log
