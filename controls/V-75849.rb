control "V-75849" do
  title "The SSH daemon must use privilege separation."
  desc  "SSH daemon privilege separation causes the SSH process to drop root
privileges when not needed, which would decrease the impact of software
vulnerabilities in the unprivileged section."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75849"
  tag "rid": "SV-90529r2_rule"
  tag "stig_id": "UBTU-16-030340"
  tag "fix_id": "F-82479r2_fix"
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
  desc "check", "Check that the SSH daemon performs privilege separation with
the following command:

# grep UsePrivilegeSeparation /etc/ssh/sshd_config

UsePrivilegeSeparation yes

If the \"UsePrivilegeSeparation\" keyword is set to \"no\", is missing, or the
returned line is commented out, this is a finding."
  desc "fix", "Configure SSH to use privilege separation. Uncomment the
\"UsePrivilegeSeparation\" keyword in \"/etc/ssh/sshd_config\" and set the
value to \"yes\":

UsePrivilegeSeparation yes

The SSH daemon must be restarted for the changes to take effect. To restart the
SSH daemon, run the following command:

# sudo systemctl restart sshd.service"

  describe sshd_config do
    its('UsePrivilegeSeparation') { should cmp 'yes' }
  end
end

