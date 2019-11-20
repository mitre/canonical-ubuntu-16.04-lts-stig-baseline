# frozen_string_literal: true

control 'V-75453' do
  title "The Ubuntu operating system must enforce password complexity by
requiring that at least one numeric character be used."
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
  tag "gtitle": 'SRG-OS-000071-GPOS-00039'
  tag "gid": 'V-75453'
  tag "rid": 'SV-90133r2_rule'
  tag "stig_id": 'UBTU-16-010120'
  tag "fix_id": 'F-82081r1_fix'
  tag "cci": ['CCI-000194']
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
by requiring that at least one numeric character be used.

Determine if the field \"dcredit\" is set in the
\"/etc/security/pwquality.conf\" file with the following command:

# grep -i \"dcredit\" /etc/security/pwquality.conf
dcredit=-1

If the \"dcredit\" parameter is not equal to \"-1\", or is commented out, this
is a finding."
  desc 'fix', "Configure the Ubuntu operating system to enforce password
complexity by requiring that at least one numeric character be used.

Add or update the following line in the \"/etc/security/pwquality.conf\" file
to contain the \"dcredit\" parameter:

dcredit=-1"

  min_num_numeric_char = input('min_num_numeric_char')
  config_file = '/etc/security/pwquality.conf'
  config_file_exists = file(config_file).exist?

  if config_file_exists
    describe parse_config_file(config_file) do
      its('ucredit') { should cmp min_num_numeric_char }
    end
  else
    describe (config_file + ' exists') do
      subject { config_file_exists }
      it { should be true }
    end
  end
end
