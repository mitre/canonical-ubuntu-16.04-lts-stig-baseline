control "V-75827" do
  title "The Ubuntu operating system must not permit direct logons to the root
account using remote access via SSH."
  desc  "Even though the communications channel may be encrypted, an additional
layer of security is gained by extending the policy of not logging on directly
as root. In addition, logging on with a user-specific account provides
individual accountability of actions performed on the system."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75827"
  tag "rid": "SV-90507r2_rule"
  tag "stig_id": "UBTU-16-030220"
  tag "fix_id": "F-82457r2_fix"
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
  desc "check", "Verify remote access using SSH prevents users from logging on
directly as \"root\".

Check that SSH prevents users from logging on directly as \"root\" with the
following command:

# grep PermitRootLogin /etc/ssh/sshd_config
PermitRootLogin no

If the \"PermitRootLogin\" keyword is set to \"yes\", is missing, or is
commented out, this is a finding."
  desc "fix", "Configure the Ubuntu operating system to stop users from logging
on remotely as the \"root\" user via SSH.

Edit the appropriate  \"/etc/ssh/sshd_config\" file to uncomment or add the
line for the \"PermitRootLogin\" keyword and set its value to \"no\":

PermitRootLogin no

The SSH daemon must be restarted for the changes to take effect. To restart the
SSH daemon, run the following command:

# sudo systemctl restart sshd.service"
end

