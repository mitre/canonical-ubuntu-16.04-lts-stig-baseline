control "V-75491" do
  title "Temporary user accounts must be provisioned with an expiration time of
72 hours or less."
  desc  "If temporary user accounts remain active when no longer needed or for
an excessive period, these accounts may be used to gain unauthorized access. To
mitigate this risk, automated termination of all temporary accounts must be set
upon account creation.

    Temporary accounts are established as part of normal account activation
procedures when there is a need for short-term accounts without the demand for
immediacy in account activation.

    If temporary accounts are used, the Ubuntu operating system must be
configured to automatically terminate these types of accounts after a
DoD-defined time period of 72 hours.

    To address access requirements, many Ubuntu operating systems may be
integrated with enterprise-level authentication/access mechanisms that meet or
exceed access control policy requirements.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000002-GPOS-00002"
  tag "gid": "V-75491"
  tag "rid": "SV-90171r1_rule"
  tag "stig_id": "UBTU-16-010310"
  tag "fix_id": "F-82119r1_fix"
  tag "cci": ["CCI-000016"]
  tag "nist": ["AC-2 (2)", "Rev_4"]
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
  desc "check", "Verify that temporary accounts have been provisioned with an
expiration date for 72 hours.

For every existing temporary account, run the following command to obtain its
account expiration information.

# sudo chage -l system_account_name

Verify each of these accounts has an expiration date set within 72 hours.
If any temporary accounts have no expiration date set or do not expire within
72 hours, this is a finding."
  desc "fix", "If a temporary account must be created configure the system to
terminate the account after a 72 hour time period with the following command to
set an expiration date on it. Substitute \"system_account_name\" with the
account to be created.

# sudo chage -E `date -d \"+3 days\" +%Y-%m-%d` system_account_name"

  temporary_accounts = attribute('temporary_accounts')

  if temporary_accounts.empty?
    describe "Temporary accounts" do
      it { should_be empty }
    end
  else
    temporary_accounts.each do |acct|
      describe command("sudo chage -l #{acct} | grep 'Account expires'") do
        its('stdout.strip') { should_not match %r{:\s*never} }
      end
    end
  end
end

