control "V-75841" do
  title "The SSH daemon must not allow authentication using known hosts
authentication."
  desc  "Configuring this setting for the SSH daemon provides additional
assurance that remote logon via SSH will require a password, even in the event
of misconfiguration elsewhere."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75841"
  tag "rid": "SV-90521r2_rule"
  tag "stig_id": "UBTU-16-030300"
  tag "fix_id": "F-82471r2_fix"
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
  desc "check", "Verify the SSH daemon does not allow authentication using known
hosts authentication.

To determine how the SSH daemon's \"IgnoreUserKnownHosts\" option is set, run
the following command:

# grep IgnoreUserKnownHosts /etc/ssh/sshd_config

IgnoreUserKnownHosts yes

If the value is returned as \"no\", the returned line is commented out, or no
output is returned, this is a finding."
  tag "fix": "Configure the SSH daemon to not allow authentication using known
hosts authentication.

Add the following line in \"/etc/ssh/sshd_config\", or uncomment the line and
set the value to \"yes\":

IgnoreUserKnownHosts yes

The SSH daemon must be restarted for the changes to take effect. To restart the
SSH daemon, run the following command:

# sudo systemctl restart sshd.service
"
end

