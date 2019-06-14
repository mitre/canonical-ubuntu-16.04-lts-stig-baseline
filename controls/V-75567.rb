exempt_home_users = attribute('exempt_home_users')
non_interactive_shells = attribute('non_interactive_shells')

control "V-75567" do
  title "All local interactive user home directories must be group-owned by the
home directory owners primary group."
  desc  "If the Group Identifier (GID) of a local interactive user’s home
directory is not the same as the primary GID of the user, this would allow
unauthorized access to the user’s files, and users that share the same group
may not be able to access files that they legitimately should."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75567"
  tag "rid": "SV-90247r1_rule"
  tag "stig_id": "UBTU-16-010760"
  tag "fix_id": "F-82195r1_fix"
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
  desc "check", "Verify the assigned home directory of all local interactive
users is group-owned by that user’s primary Group Identifier (GID).

Check the home directory assignment for all non-privileged users on the system
with the following command:

Note: This may miss local interactive users that have been assigned a
privileged UID. Evidence of interactive use may be obtained from a number of
log files containing system logon information. The returned directory
\"/home/smithj\" is used as an example.

# ls -ld $(awk -F: '($3>=1000)&&($1!=\"nobody\"){print $6}' /etc/passwd)

drwxr-x--- 2 smithj admin 4096 Jun 5 12:41 smithj

Check the user's primary group with the following command:

# grep admin /etc/group
admin:x:250:smithj,jonesj,jacksons

If the user home directory referenced in \"/etc/passwd\" is not group-owned by
that user’s primary GID, this is a finding."
  desc "fix", "Change the group owner of a local interactive user’s home
directory to the group found in \"/etc/passwd\". To change the group owner of a
local interactive user’s home directory, use the following command:

Note: The example will be for the user \"smithj\", who has a home directory of
\"/home/smithj\", and has a primary group of users.

# chgrp users /home/smithj"

  ignore_shells = non_interactive_shells.join('|')

  findings = Set[]
  users.where{ !shell.match(ignore_shells) && (uid >= 1000 || uid == 0)}.entries.each do |user_info|
    next if exempt_home_users.include?("#{user_info.username}")
    findings = findings + command("find #{user_info.home} -maxdepth 0 -not -gid #{user_info.gid}").stdout.split("\n")
  end
  describe "Home directories that are not group-owned by the user's primary GID" do
    subject { findings.to_a }
    it { should be_empty }
  end
end

