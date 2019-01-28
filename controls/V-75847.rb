control "V-75847" do
  title "The SSH daemon must perform strict mode checking of home directory
configuration files."
  desc  "If other users have access to modify user-specific SSH configuration
files, they may be able to log on to the system as another user."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75847"
  tag "rid": "SV-90527r2_rule"
  tag "stig_id": "UBTU-16-030330"
  tag "fix_id": "F-82477r2_fix"
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
  desc "check", "Verify the SSH daemon performs strict mode checking of home
directory configuration files.

Check that the SSH daemon performs strict mode checking of home directory
configuration files with the following command:

# grep StrictModes /etc/ssh/sshd_config

StrictModes yes

If \"StrictModes\" is set to \"no\", is missing, or the returned line is
commented out, this is a finding."
  tag "fix": "Configure SSH to perform strict mode checking of home directory
configuration files. Uncomment the \"StrictModes\" keyword in
\"/etc/ssh/sshd_config\" and set the value to \"yes\":

StrictModes yes

The SSH daemon must be restarted for the changes to take effect. To restart the
SSH daemon, run the following command:

# sudo systemctl restart sshd.service"
end

