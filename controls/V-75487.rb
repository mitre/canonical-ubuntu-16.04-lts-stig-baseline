# frozen_string_literal: true

control 'V-75487' do
  title "The Ubuntu operating system must automatically lock an account until
the locked account is released by an administrator when three unsuccessful
logon attempts."
  desc  "By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-forcing, is reduced. Limits are imposed by locking the account.


  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000021-GPOS-00005'
  tag "satisfies": %w[SRG-OS-000021-GPOS-00005 SRG-OS-000329-GPOS-00128]
  tag "gid": 'V-75487'
  tag "rid": 'SV-90167r2_rule'
  tag "stig_id": 'UBTU-16-010290'
  tag "fix_id": 'F-82115r2_fix'
  tag "cci": %w[CCI-000044 CCI-002238]
  tag "nist": ['AC-7 a', 'AC-7 b', 'Rev_4']
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
  desc 'check', "Verify the Ubuntu operating system automatically locks an
account until the account lock is released by an administrator when three
unsuccessful logon attempts are made.

Check that the Ubuntu operating system automatically locks an account after
three unsuccessful attempts with the following command:

# grep pam_tally /etc/pam.d/common-auth

auth required pam_tally2.so onerr=fail deny=3

If \"onerr=fail deny=3\" is not used in \"/etc/pam.d/common-auth\" or is called
with \"unlock_time\", this is a finding."
  desc 'fix', "Configure the Ubuntu operating system to automatically lock an
account until the locked account is released by an administrator when three
unsuccessful logon attempts are made by appending the following line to the
\"/etc/pam.d/common-auth file\":

\"auth required pam_tally2.so onerr=fail deny=3\""

  describe file('/etc/pam.d/common-auth') do
    it { should exist }
  end

  describe command('grep pam_tally /etc/pam.d/common-auth') do
    its('exit_status') { should eq 0 }
    its('stdout.strip') { should match /^\s*auth\s+required\s+pam_tally2.so\s+.*onerr=fail\s+deny=3($|\s+.*$)/ }
    its('stdout.strip') { should_not match /^\s*auth\s+required\s+pam_tally2.so\s+.*onerr=fail\s+deny=3\s+.*unlock_time.*$/ }
  end
end
