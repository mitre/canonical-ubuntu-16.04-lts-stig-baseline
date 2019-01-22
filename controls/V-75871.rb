control "V-75871" do
  title "For Ubuntu operating systems using Domain Name Servers (DNS)
resolution, at least two name servers must be configured."
  desc  "To provide availability for name resolution services, multiple
redundant name servers are mandated. A failure in name resolution could lead to
the failure of security functions requiring name resolution, which may include
time synchronization, centralized authentication, and remote system logging."
  impact 0.3
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75871"
  tag "rid": "SV-90551r2_rule"
  tag "stig_id": "UBTU-16-030520"
  tag "fix_id": "F-82501r2_fix"
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
  tag "check": "Determine whether the Ubuntu operating system is using local or
Domain Name Server (DNS) name resolution with the following command:

# grep hosts /etc/nsswitch.conf
hosts:   files dns

If the DNS entry is missing from the host’s line in the \"/etc/nsswitch.conf\"
file, the \"/etc/resolv.conf\" file must be empty.

If the \"/etc/resolv.conf\" file is not empty, this is a finding.

If the DNS entry is found on the host’s line of the \"/etc/nsswitch.conf\"
file, verify the Ubuntu operating system is configured to use two or more name
servers for DNS resolution.

Determine the name servers used by the system with the following command:

# sudo grep nameserver /etc/resolv.conf

nameserver 192.168.1.2

nameserver 192.168.1.3

If less than two lines are returned that are not commented out, this is a
finding."
  tag "fix": "Configure the Ubuntu operating system to use two or more name
servers for Domain Name Server (DNS) resolution.

Edit the \"/etc/resolv.conf\" file to uncomment or add the two or more
\"nameserver\" option lines with the IP address of local authoritative name
servers. If local host resolution is being performed, the \"/etc/resolv.conf\"
file must be empty. An empty \"/etc/resolv.conf\" file can be created as
follows:

# echo -n > /etc/resolv.conf"
end

