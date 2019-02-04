control "V-75883" do
  title "The Ubuntu operating system must not allow interfaces to perform
Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP)
redirects by default."
  desc  "Internet Control Message Protocol (ICMP) redirect messages are used by
routers to inform hosts that a more direct route exists for a particular
destination. These messages contain information from the system's route table,
possibly revealing portions of the network topology."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75883"
  tag "rid": "SV-90563r2_rule"
  tag "stig_id": "UBTU-16-030580"
  tag "fix_id": "F-82513r2_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc "check", "Verify the Ubuntu operating system does not allow interfaces to
perform Internet Protocol version 4 (IPv4) Internet Control Message Protocol
(ICMP) redirects by default.

Check the value of the \"default send_redirects\" variables with the following
command:

# sudo sysctl net.ipv4.conf.default.send_redirects

net.ipv4.conf.default.send_redirects=0

If the returned line does not have a value of \"0\", or a line is not returned,
this is a finding."
  desc "fix", "Configure the Ubuntu operating system to not allow interfaces to
perform Internet Protocol version 4 (IPv4) Internet Control Message Protocol
(ICMP) redirects by default with the following command:

# sudo sysctl -w net.ipv4.conf.default.send_redirects=0

If \"0\" is not the system's default value then add or update the following
line in \"/etc/sysctl.conf\" or in the appropriate file under \"/etc/sysctl.d\":

net.ipv4.conf.default.send_redirects=0"
end

