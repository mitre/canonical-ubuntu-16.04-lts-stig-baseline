control "V-75875" do
  title "The Ubuntu operating system must not forward Internet Protocol version
4 (IPv4) source-routed packets by default."
  desc  "Source-routed packets allow the source of the packet to suggest that
routers forward the packet along a different path than configured on the
router, which can be used to bypass network security measures. This requirement
applies only to the forwarding of source-routed traffic, such as when IPv4
forwarding is enabled and the system is functioning as a router."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75875"
  tag "rid": "SV-90555r3_rule"
  tag "stig_id": "UBTU-16-030540"
  tag "fix_id": "F-82505r3_fix"
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
  desc "check", "Verify the Ubuntu operating system does not accept  Internet
Protocol version 4 (IPv4) source-routed packets by default.

Check the value of the accept source route variable with the following command:

# sudo sysctl net.ipv4.conf.default.accept_source_route
net.ipv4.conf.default.accept_source_route=0

If the returned line does not have a value of \"0\", a line is not returned, or
the returned line is commented out, this is a finding."
  desc "fix", "Configure the Ubuntu operating system to not forward Internet
Protocol version 4 (IPv4) source-routed packets by default with the following
command:

# sudo sysctl -w net.ipv4.conf.default.accept_source_route=0

If \"0\" is not the system's default value then add or update the following
line in \"/etc/sysctl.conf\" or in the appropriate file under \"/etc/sysctl.d\":

net.ipv4.conf.default.accept_source_route=0"

  describe command('sysctl net.ipv4.conf.default.accept_source_route') do
    its('stdout') { should match %r((net\.ipv4\.conf\.default\.accept_source_route) *= *(0)) }
  end
end

