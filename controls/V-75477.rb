control "V-75477" do
  title "Passwords must have a minimum of 15-characters."
  desc  "The shorter the password, the lower the number of possible
combinations that need to be tested before the password is compromised.

    Password complexity, or strength, is a measure of the effectiveness of a
password in resisting attempts at guessing and brute-force attacks. Password
length is one factor of several that helps to determine strength and how long
it takes to crack a password. Use of more characters in a password helps to
exponentially increase the time and/or resources required to compromise the
password.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000078-GPOS-00046"
  tag "gid": "V-75477"
  tag "rid": "SV-90157r2_rule"
  tag "stig_id": "UBTU-16-010240"
  tag "fix_id": "F-82105r1_fix"
  tag "cci": ["CCI-000205"]
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
  desc "check", "Verify that the Ubuntu operating system enforces a minimum
\"15\" character password length, by running the following command:

# grep -i minlen /etc/security/pwquality.conf
 minlen=15

If \"minlen\" parameter value is not \"15\" or higher, or is commented out,
this is a finding."
  tag "fix": "Configure the Ubuntu operating system to enforce a minimum
15-character password length.

Add, or modify the \"minlen\" parameter value to the following line in
\"/etc/security/pwquality.conf\" file:

minlen=15"

  describe package('libpam-pwquality') do
    it { should be_installed }
  end

  describe file("/etc/security/pwquality.conf") do
    it { should exist }
  end

  describe command('grep -i minlen /etc/security/pwquality.conf') do
    its('exit_status') { should eq 0 }
    its('stdout.strip') { should match /^minlen\s*=\s*([1][5-9]|[2-9][\d]+|[1-9][\d][\d]+)$/ }
  end
end

