control "V-75545" do
  title "The Ubuntu operating system must not have unnecessary accounts."
  desc  "Accounts providing no operational purpose provide additional
opportunities for system compromise. Unnecessary accounts include user accounts
for individuals not requiring access to the system and application accounts for
applications not installed on the system."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75545"
  tag "rid": "SV-90225r2_rule"
  tag "stig_id": "UBTU-16-010650"
  tag "fix_id": "F-82173r1_fix"
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
  desc "check", "Verify all accounts on the system are assigned to an active
system, application, or user account.

Obtain the list of authorized system accounts from the Information System
Security Officer (ISSO).

Check the system accounts on the system with the following command:

# more /etc/passwd
root:x:0:0:root:/root:/bin/bash
...
games:x:5:60:games:/usr/games:/usr/sbin/nologin

Accounts such as \"games\" and \"gopher\" are not authorized accounts as they
do not support authorized system functions.

If the accounts on the system do not match the provided documentation, or
accounts that do not support an authorized system function are present, this is
a finding."
  desc "fix", "Configure the system so all accounts on the system are assigned
to an active system, application, or user account.

Remove accounts that do not support approved system activities or that allow
for a normal user to perform administrative-level actions.

Document all authorized accounts on the system."

  known_system_accounts = input('known_system_accounts')
  disallowed_accounts = input('disallowed_accounts')
  user_accounts = input('user_accounts')
  allowed_accounts = (known_system_accounts + user_accounts).uniq

  describe "The active system users" do
    subject { passwd }
    its('users') { should be_in allowed_accounts }
    its('users') { should_not be_in disallowed_accounts }
  end
  # describe "System" do
  #   subject { passwd }
    
  # end
end

