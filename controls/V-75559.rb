exempt_home_users = attribute('exempt_home_users')
non_interactive_shells = attribute('non_interactive_shells')

control "V-75559" do
  title "All local interactive users must have a home directory assigned in the
/etc/passwd file."
  desc  "If local interactive users are not assigned a valid home directory,
there is no place for the storage and control of files they should own."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75559"
  tag "rid": "SV-90239r1_rule"
  tag "stig_id": "UBTU-16-010720"
  tag "fix_id": "F-82187r1_fix"
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
  desc "check", "Verify local interactive users on the Ubuntu operating system
have a home directory assigned.

Check for missing local interactive user home directories with the following
command:

# sudo pwck -r
user 'lp': directory '/var/spool/lpd' does not exist
user 'news': directory '/var/spool/news' does not exist
user 'uucp': directory '/var/spool/uucp' does not exist
user 'www-data': directory '/var/www' does not exist

Ask the System Administrator (SA) if any users found without home directories
are local interactive users. If the SA is unable to provide a response, check
for users with a User Identifier (UID) of 1000 or greater with the following
command:

# sudo cut -d: -f 1,3 /etc/passwd | egrep \":[1-4][0-9]{2}$|:[0-9]{1,2}$\"

If any interactive users do not have a home directory assigned, this is a
finding."
  desc "fix", "Assign home directories to all local interactive users on the
Ubuntu operating system that currently do not have a home directory assigned."

  ignore_shells = non_interactive_shells.join('|')

  users.where{ !shell.match(ignore_shells) && (uid >= 1000 || uid == 0)}.entries.each do |user_info|
    next if exempt_home_users.include?("#{user_info.username}")
    describe directory(user_info.home) do
      it { should exist }
    end
  end
end

