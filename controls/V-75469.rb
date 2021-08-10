# frozen_string_literal: true

control 'V-75469' do
  title "Emergency administrator accounts must never be automatically removed
or disabled."
  desc  "Emergency accounts are privileged accounts that are established in
response to crisis situations where the need for rapid account activation is
required. Therefore, emergency account activation may bypass normal account
authorization processes. If these accounts are automatically disabled, system
maintenance during emergencies may not be possible, thus adversely affecting
system availability.

    Emergency accounts are different from infrequently used accounts (i.e.,
local logon accounts used by the organization's system administrators when
network or normal logon/access is not available). Infrequently used accounts
are not subject to automatic termination dates. Emergency accounts are accounts
created in response to crisis situations, usually for use by maintenance
personnel. The automatic expiration or disabling time period may be extended as
needed until the crisis is resolved; however, it must not be extended
indefinitely. A permanent account should be established for privileged users
who need long-term maintenance accounts.

    To address access requirements, many Ubuntu operating systems can be
integrated with enterprise-level authentication/access mechanisms that meet or
exceed access control policy requirements.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000123-GPOS-00064'
  tag "gid": 'V-75469'
  tag "rid": 'SV-90149r1_rule'
  tag "stig_id": 'UBTU-16-010200'
  tag "fix_id": 'F-82097r1_fix'
  tag "cci": ['CCI-001682']
  tag "nist": ['AC-2 (2)', 'Rev_4']
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
  desc 'check', "Verify the Ubuntu operating system is configured such that the
emergency administrator account is never automatically removed or disabled.

Check to see if the root account password or account expires with the following
command:

# sudo chage -l root

Password expires :never

If \"Password expires\" or \"Account expires\" is set to anything other than
\"never\", this is a finding."
  desc 'fix', "Replace \"[Emergency_Administrator]\" in the following command
with the correct emergency administrator account. Run the following command as
an administrator:

# sudo chage -I -1 -M 99999 [Emergency_Administrator]"

  emergency_accounts = input('emergency_accounts')

  if emergency_accounts.empty?
    describe 'Emergency accounts' do
      subject { emergency_accounts }
      it { should be_empty }
    end
    describe shadow.where(user: 'root') do
      its('expiry_dates') { should eq [nil] }
    end
  else
    emergency_accounts.each do |acct|
      describe command("sudo chage -l #{acct} | grep 'Account expires'") do
        its('stdout.strip') { should_not match /:\s*never/ }
      end
    end
  end
end
