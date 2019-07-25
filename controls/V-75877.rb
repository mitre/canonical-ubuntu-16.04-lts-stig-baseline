control "V-75877" do
  title "The Ubuntu operating system must not respond to Internet Protocol
version 4 (IPv4) Internet Control Message Protocol (ICMP) echoes sent to a
broadcast address."
  desc  "Responding to broadcast Internet Control Message Protocol (ICMP)
echoes facilitates network mapping and provides a vector for amplification
attacks."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75877"
  tag "rid": "SV-90557r2_rule"
  tag "stig_id": "UBTU-16-030550"
  tag "fix_id": "F-82507r2_fix"
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
  desc "check", "Verify the Ubuntu operating system does not respond to IPv4
Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.

Check the value of the \"icmp_echo_ignore_broadcasts\" variable with the
following command:

# sudo sysctl net.ipv4.icmp_echo_ignore_broadcasts
net.ipv4.icmp_echo_ignore_broadcasts=1

If the returned line does not have a value of \"1\", a line is not returned, or
the retuned line is commented out, this is a finding."
  desc "fix", "Configure the Ubuntu operating system to not respond to Internet
Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) echoes sent
to a broadcast address with the following command:

# sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1

If \"1\" is not the system's default value then add or update the following
line in \"/etc/sysctl.conf\" or in the appropriate file under \"/etc/sysctl.d\":

net.ipv4.icmp_echo_ignore_broadcasts=1"

  describe kernel_parameter('net.ipv4.icmp_echo_ignore_broadcasts') do
    its('value') { should eq 1 }
  end
end

