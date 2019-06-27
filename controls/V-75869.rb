control "V-75869" do
  title "The Ubuntu operating system must be configured to use TCP syncookies."
  desc  "DoS is a condition when a resource is not available for legitimate
users. When this occurs, the organization either cannot accomplish its mission
or must operate at degraded capacity.

    Managing excess capacity ensures that sufficient capacity is available to
counter flooding attacks. Employing increased capacity and service redundancy
may reduce the susceptibility to some DoS attacks. Managing excess capacity may
include, for example, establishing selected usage priorities, quotas, or
partitioning.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000142-GPOS-00071"
  tag "gid": "V-75869"
  tag "rid": "SV-90549r2_rule"
  tag "stig_id": "UBTU-16-030510"
  tag "fix_id": "F-82499r2_fix"
  tag "cci": ["CCI-001095"]
  tag "nist": ["SC-5 (2)", "Rev_4"]
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
  desc "check", "Verify the Ubuntu operating system is configured to use TCP
syncookies.

Check the value of TCP syncookies with the following command:

# sysctl net.ipv4.tcp_syncookies
net.ipv4.tcp_syncookies = 1

If the value is not \"1\", this is a finding."
  desc "fix", "Configure the Ubuntu operating system to use TCP syncookies, by
running the following command:

# sudo sysctl -w net.ipv4.tcp_syncookies=1

If \"1\" is not the system's default value then add or update the following
line in \"/etc/sysctl.conf\" or in the appropriate file under \"/etc/sysctl.d\":

net.ipv4.tcp_syncookies = 1"

  describe command('sysctl net.ipv4.tcp_syncookies') do
    its('stdout') { should match %r((net\.ipv4\.tcp_syncookies) *= *(1)) }
  end
end

