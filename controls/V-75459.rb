control "V-75459" do
  title "The Ubuntu operating system must encrypt all stored passwords with a
FIPS 140-2 approved cryptographic hashing algorithm."
  desc  "Passwords need to be protected at all times, and encryption is the
standard method for protecting passwords. If passwords are not encrypted, they
can be plainly read (i.e., clear text) and easily compromised.

    Unapproved mechanisms that are used for authentication to the cryptographic
module are not verified and therefore cannot be relied upon to provide
confidentiality or integrity, and DoD data may be compromised.

    FIPS 140-2 is the current standard for validating that mechanisms used to
access cryptographic modules utilize authentication that meets DoD requirements.


  "
  impact 0.5
  tag "gtitle": "SRG-OS-000073-GPOS-00041"
  tag "satisfies": ["SRG-OS-000073-GPOS-00041", "SRG-OS-000120-GPOS-00061"]
  tag "gid": "V-75459"
  tag "rid": "SV-90139r1_rule"
  tag "stig_id": "UBTU-16-010150"
  tag "fix_id": "F-82087r1_fix"
  tag "cci": ["CCI-000196", "CCI-000803"]
  tag "nist": ["IA-5 (1) (c)", "IA-7", "Rev_4"]
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
  desc "check", "Verify that the shadow password suite configuration is set to
encrypt password with a FIPS 140-2 approved cryptographic hashing algorithm.

Check the hashing algorithm that is being used to hash passwords with the
following command:

# cat /etc/login.defs | grep -i crypt

ENCRYPT_METHOD SHA512

If \"ENCRYPT_METHOD\" does not equal SHA512 or greater, this is a finding."
  tag "fix": "Configure the Ubuntu operating system to encrypt all stored
passwords.

Edit/Modify the following line in the \"/etc/login.defs\" file and set
\"[ENCRYPT_METHOD]\" to SHA512.

ENCRYPT_METHOD SHA512"
end

