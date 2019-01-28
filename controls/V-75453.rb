control "V-75453" do
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
  tag "gtitle": "SRG-OS-000071-GPOS-00039"
  tag "gid": "V-75453"
  tag "rid": "SV-90133r2_rule"
  tag "stig_id": "UBTU-16-010120"
  tag "fix_id": "F-82081r1_fix"
  tag "cci": ["CCI-000194"]
  tag "nist": ["IA-5 (1) (a)", "Rev_4"]
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
  desc "check", "Verify the Ubuntu operating system enforces password complexity
by requiring that at least one numeric character be used.

Determine if the field \"dcredit\" is set in the
\"/etc/security/pwquality.conf\" file with the following command:

# grep -i \"dcredit\" /etc/security/pwquality.conf
dcredit=-1

If the \"dcredit\" parameter is not equal to \"-1\", or is commented out, this
is a finding."
  tag "fix": "Configure the Ubuntu operating system to enforce password
complexity by requiring that at least one numeric character be used.

Add or update the following line in the \"/etc/security/pwquality.conf\" file
to contain the \"dcredit\" parameter:

dcredit=-1"

  describe package('libpam-pwquality') do
    it { should be_installed }
  end

  describe file("/etc/security/pwquality.conf") do
    it { should exist }
  end

  describe command('grep -i dcredit /etc/security/pwquality.conf') do
    its('exit_status') { should eq 0 }
    its('stdout') { should match /^[\s]*dcredit[\s]*=[\s]*-[1-9][\d]*$/ }
  end
end

