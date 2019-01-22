control "V-75565" do
  title "All local interactive user home directories must have mode 0750 or
less permissive."
  desc  "Excessive permissions on local interactive user home directories may
allow unauthorized access to user files by other users."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75565"
  tag "rid": "SV-90245r1_rule"
  tag "stig_id": "UBTU-16-010750"
  tag "fix_id": "F-82193r1_fix"
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
  tag "check": "Verify the assigned home directory of all local interactive
users has a mode of \"0750\" or less permissive.

Check the home directory assignment for all non-privileged users with the
following command:

Note: This may miss interactive users that have been assigned a privileged User
Identifier (UID). Evidence of interactive use may be obtained from a number of
log files containing system logon information.

# ls -ld $(awk -F: '($3>=1000)&&($1!=\"nobody\"){print $6}' /etc/passwd)

drwxr-x--- 2 smithj admin 4096 Jun 5 12:41 smithj

If home directories referenced in \"/etc/passwd\" do not have a mode of
\"0750\" or less permissive, this is a finding."
  tag "fix": "Change the mode of interactive user’s home directories to
\"0750\". To change the mode of a local interactive user’s home directory, use
the following command:

Note: The example will be for the user \"smithj\".

# chmod 0750 /home/smithj"
end

