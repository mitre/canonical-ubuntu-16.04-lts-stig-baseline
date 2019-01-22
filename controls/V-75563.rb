control "V-75563" do
  title "All local interactive user home directories defined in the /etc/passwd
file must exist."
  desc  "If a local interactive user has a home directory defined that does not
exist, the user may be given access to the / directory as the current working
directory upon logon. This could create a Denial of Service because the user
would not be able to access their logon configuration files, and it may give
them visibility to system files they normally would not be able to access."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75563"
  tag "rid": "SV-90243r1_rule"
  tag "stig_id": "UBTU-16-010740"
  tag "fix_id": "F-82191r1_fix"
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
users on the Ubuntu operating system exists.

Check the home directory assignment for all local interactive non-privileged
users with the following command:

# ls -ld $(awk -F: '($3>=1000)&&($1!=\"nobody\"){print $6}' /etc/passwd)

drwxr-xr-x 2 smithj admin 4096 Jun 5 12:41 smithj

Note: This may miss interactive users that have been assigned a privileged User
ID (UID). Evidence of interactive use may be obtained from a number of log
files containing system logon information.

Check that all referenced home directories exist with the following command:

# pwck -r

user 'smithj': directory '/home/smithj' does not exist

If any home directories referenced in \"/etc/passwd\" are returned as not
defined, this is a finding."
  tag "fix": "Create home directories to all local interactive users that
currently do not have a home directory assigned. Use the following commands to
create the user home directory assigned in \"/etc/ passwd\":

Note: The example will be for the user smithj, who has a home directory of
\"/home/smithj\", a User ID (UID) of \"smithj\", and a Group Identifier (GID)
of \"users assigned\" in \"/etc/passwd\".

# mkdir /home/smithj
# chown smithj /home/smithj
# chgrp users /home/smithj
# chmod 0750 /home/smithj"
end

