control "V-75835" do
  title "The system must display the date and time of the last successful
account logon upon an SSH logon."
  desc  "Providing users with feedback on when account accesses via SSH last
occurred facilitates user recognition and reporting of unauthorized account
use."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75835"
  tag "rid": "SV-90515r2_rule"
  tag "stig_id": "UBTU-16-030260"
  tag "fix_id": "F-82465r2_fix"
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
  desc "check", "Verify SSH provides users with feedback on when account
accesses last occurred.

Check that \"PrintLastLog\" keyword in the sshd daemon configuration file is
used and set to \"yes\" with the following command:

# grep PrintLastLog /etc/ssh/sshd_config
PrintLastLog yes

If the \"PrintLastLog\" keyword is set to \"no\", is missing, or is commented
out, this is a finding."
  desc "fix", "Add or edit the following lines in the \"/etc/ssh/sshd_config\"
file:

PrintLastLog yes

The SSH daemon must be restarted for the changes to take effect. To restart the
SSH daemon, run the following command:

# sudo systemctl restart sshd.service"
end

