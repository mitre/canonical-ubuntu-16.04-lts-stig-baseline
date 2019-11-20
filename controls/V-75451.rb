# frozen_string_literal: true

control 'V-75451' do
  title "The Ubuntu operating system must enforce password complexity by
requiring that at least one lower-case character be used."
  desc  "Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks.

    Password complexity is one factor of several that determines how long it
takes to crack a password. The more complex the password, the greater the
number of possible combinations that need to be tested before the password is
compromised.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000070-GPOS-00038'
  tag "gid": 'V-75451'
  tag "rid": 'SV-90131r2_rule'
  tag "stig_id": 'UBTU-16-010110'
  tag "fix_id": 'F-82079r1_fix'
  tag "cci": ['CCI-000193']
  tag "nist": ['IA-5 (1) (a)', 'Rev_4']
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
  desc 'check', "Verify the Ubuntu operating system enforces password complexity
by requiring that at least one lower-case character be used.

Determine if the field \"lcredit\" is set in the
\"/etc/security/pwquality.conf\" file with the following command:

# grep -i \"lcredit\" /etc/security/pwquality.conf
lcredit=-1

If the \"lcredit\" parameter is not equal to \"-1\", or is commented out, this
is a finding."
  desc 'fix', "Configure the Ubuntu operating system to enforce password
complexity by requiring that at least one lower-case character be used.

Add or update the following line in the \"/etc/security/pwquality.conf\" file
to contain the \"lcredit\" parameter:

lcredit=-1"

  min_num_lowercase_char = input('min_num_lowercase_char')
  config_file = '/etc/security/pwquality.conf'
  config_file_exists = file(config_file).exist?

  if config_file_exists
    describe parse_config_file(config_file) do
      its('lcredit') { should cmp min_num_lowercase_char }
    end
  else
    describe (config_file + ' exists') do
      subject { config_file_exists }
      it { should be true }
    end
  end
end
