control "V-75805" do
  title "An application firewall must be enabled on the system."
  desc  "Firewalls protect computers from network attacks by blocking or
limiting access to open network ports. Application firewalls limit which
applications are allowed to communicate over the network."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00232"
  tag "gid": "V-75805"
  tag "rid": "SV-90485r2_rule"
  tag "stig_id": "UBTU-16-030040"
  tag "fix_id": "F-82435r2_fix"
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
  desc "check", "Verify the Uncomplicated Firewall is enabled on the system by
running the following command:

# sudo systemctl is-enabled ufw

enabled

If the above command returns the status as \"disabled\", this is a finding.

If the Uncomplicated Firewall is not installed, ask the System Administrator if
another application firewall is installed. If no application firewall is
installed this is a finding."
  desc "fix", "Enable the Uncomplicated Firewall by using the following commands:

# sudo systemctl start ufw

# sudo systemctl enable ufw
"
end

