# frozen_string_literal: true

control 'V-75481' do
  title "The Ubuntu operating system must prevent the use of dictionary words
for passwords."
  desc  "If the Ubuntu operating system allows the user to select passwords
based on dictionary words, this increases the chances of password compromise by
increasing the opportunity for successful guesses and brute-force attacks."
  impact 0.5
  tag "gtitle": 'SRG-OS-000480-GPOS-00225'
  tag "gid": 'V-75481'
  tag "rid": 'SV-90161r3_rule'
  tag "stig_id": 'UBTU-16-010260'
  tag "fix_id": 'F-82109r2_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
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
  desc 'check', "Verify the Ubuntu operating system prevents the use of
dictionary words for passwords.

Check that the Ubuntu operating system uses the cracklib library to prevent the
use of dictionary words with the following command:

# grep dictcheck /etc/security/pwquality.conf

dictcheck=1

If the \"dictcheck\" parameter is not set to \"1\", or is commented out, this
is a finding."
  desc 'fix', "Configure the Ubuntu operating system to prevent the use of
dictionary words for passwords.

Edit the file \"/etc/security/pwquality.conf\" by adding a line such as:

dictcheck=1"

  config_file = '/etc/security/pwquality.conf'
  config_file_exists = file(config_file).exist?

  if config_file_exists
    describe parse_config_file(config_file) do
      its('dictcheck') { should cmp '1' }
    end
  else
    describe (config_file + ' exists') do
      subject { config_file_exists }
      it { should be true }
    end
  end
end
