# frozen_string_literal: true

control 'V-75463' do
  title "The Ubuntu operating system must employ FIPS 140-2 approved
cryptographic hashing algorithms for all created passwords."
  desc  "The system must use a strong hashing algorithm to store the password.
The system must use a sufficient number of hashing rounds to ensure the
required level of entropy.

    Passwords need to be protected at all times, and encryption is the standard
method for protecting passwords. If passwords are not encrypted, they can be
plainly read (i.e., clear text) and easily compromised.


  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000073-GPOS-00041'
  tag "satisfies": %w[SRG-OS-000073-GPOS-00041 SRG-OS-000120-GPOS-00061]
  tag "gid": 'V-75463'
  tag "rid": 'SV-90143r2_rule'
  tag "stig_id": 'UBTU-16-010170'
  tag "fix_id": 'F-82091r2_fix'
  tag "cci": %w[CCI-000196 CCI-000803]
  tag "nist": ['IA-5 (1) (c)', 'IA-7', 'Rev_4']
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
  desc 'check', "Verify the shadow password suite configuration is set to create
passwords using a strong cryptographic hash with the following command:

Check that a minimum number of hash rounds is configured by running the
following command:

# grep rounds /etc/pam.d/common-password

password  [success=1 default=ignore]  pam_unix.so obscure sha512 rounds=5000

If \"rounds\" has a value below \"5000\", or is commented out, this is a
finding.
"
  desc 'fix', "Configure the Ubuntu operating system to encrypt all stored
passwords with a strong cryptographic hash.

Edit/modify the following line in the \"/etc/pam.d/common-password\" file and
set \"rounds\" to a value no lower than \"5000\":

password  [success=1 default=ignore]  pam_unix.so obscure sha512 rounds=5000"

  describe file('/etc/pam.d/common-password') do
    it { should exist }
  end

  describe command('grep rounds /etc/pam.d/common-password') do
    its('exit_status') { should eq 0 }
    its('stdout') { should match /^\s*password\s+\[\s*success=1\s+default=ignore\s*\].*\s+rounds=([5-9]\d\d\d|[1-9]\d\d\d\d+)($|\s+.*$)/ }
  end
end
