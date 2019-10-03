# frozen_string_literal: true

control 'V-75483' do
  title "The passwd command must be configured to prevent the use of dictionary
words as passwords."
  desc  "If the Ubuntu operating system allows the user to select passwords
based on dictionary words, this increases the chances of password compromise by
increasing the opportunity for successful guesses and brute-force attacks."
  impact 0.5
  tag "gtitle": 'SRG-OS-000480-GPOS-00225'
  tag "gid": 'V-75483'
  tag "rid": 'SV-90163r1_rule'
  tag "stig_id": 'UBTU-16-010270'
  tag "fix_id": 'F-82111r1_fix'
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
  desc 'check', "Verify the \"passwd\" command uses the common-password settings.

Check that the \"passwd\" command uses the common-password option with the
following command:

# grep common-password /etc/pam.d/passwd

@ include common-password

If the command does not return a line, or the line is commented out, this is a
finding."
  desc 'fix', "Configure the Ubuntu operating system to prevent the use of
dictionary words for passwords.

Edit the file \"/etc/pam.d/passwd\" and add the following line:

@ include common-password"

  describe file('/etc/pam.d/passwd') do
    it { should exist }
  end

  describe command('grep common-password /etc/pam.d/passwd') do
    its('exit_status') { should eq 0 }
    its('stdout.strip') { should match /^@\s*include\s+common-password$/ }
  end
end
