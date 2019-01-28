control "V-75465" do
  title "The pam_unix.so module must use a FIPS 140-2 approved cryptographic
hashing algorithm for system authentication."
  desc  "Unapproved mechanisms that are used for authentication to the
cryptographic module are not verified and therefore cannot be relied upon to
provide confidentiality or integrity, and DoD data may be compromised.

    Ubuntu operating systems utilizing encryption are required to use
FIPS-compliant mechanisms for authenticating to cryptographic modules.

    FIPS 140-2 is the current standard for validating that mechanisms used to
access cryptographic modules utilize authentication that meets DoD
requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a
general purpose computing system.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000120-GPOS-00061"
  tag "gid": "V-75465"
  tag "rid": "SV-90145r2_rule"
  tag "stig_id": "UBTU-16-010180"
  tag "fix_id": "F-82093r2_fix"
  tag "cci": ["CCI-000803"]
  tag "nist": ["IA-7", "Rev_4"]
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
  desc "check", "Verify that pam_unix.so auth is configured to use sha512.

Check that pam_unix.so auth is configured to use sha512 with the following
command:

# grep password /etc/pam.d/common-password | grep pam_unix

password        [success=1 default=ignore]      pam_unix.so obscure sha512

If \"sha512\" is not an option of the output, or is commented out, this is a
finding."
  tag "fix": "Configure the Ubuntu operating system to use a FIPS 140-2
approved cryptographic hashing algorithm for system authentication.

Edit/modify the following line in the file \"/etc/pam.d/common-password\" file
to include the sha512 option for pam_unix.so:

password        [success=1 default=ignore]      pam_unix.so obscure sha512
shadow remember=5"

  describe file("/etc/pam.d/common-password") do
    it { should exist }
  end

  describe command("grep rounds /etc/pam.d/common-password") do
    its('exit_status') { should eq 0 }
    its('stdout') { should match /^[\s]*password[\s]+\[[\s]*success=1[\s]+default=ignore[\s]*\].*[\s]+sha512($|[\s]+.*$)/ }
  end

end

