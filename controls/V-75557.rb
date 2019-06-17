exempt_home_users = input('exempt_home_users')
non_interactive_shells = input('non_interactive_shells')

control "V-75557" do
  title "All files and directories must have a valid group owner."
  desc  "Files without a valid group owner may be unintentionally inherited if
a group is assigned the same Group Identifier (GID) as the GID of the files
without a valid group owner."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75557"
  tag "rid": "SV-90237r1_rule"
  tag "stig_id": "UBTU-16-010710"
  tag "fix_id": "F-82185r1_fix"
  tag "cci": ["CCI-002165"]
  tag "nist": ["AC-3 (4)", "Rev_4"]
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
  desc "check", "Verify all files and directories on the Ubuntu operating system
have a valid group.

Check the owner of all files and directories with the following command:

# sudo find / -nogroup

If any files on the system do not have an assigned group, this is a finding."
  desc "fix", "Either remove all files and directories from the Ubuntu operating
system that do not have a valid group, or assign a valid group to all files and
directories on the system with the \"chgrp\" command:

# sudo chgrp <group> <file>"

ignore_shells = non_interactive_shells.join('|')

findings = Set[]
users.where{ !shell.match(ignore_shells) }.entries.each do |user_info|
  next if exempt_home_users.include?("#{user_info.username}")
  findings = findings + command("find / -nogroup").stdout.split("\n")
end

describe "Files and Directories on the Ubuntu operating system have a valid group" do
  subject { findings.to_a }
  it { should be_empty }
end
end

