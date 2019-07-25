control "V-75503" do
  title "The Ubuntu operating system must implement NSA-approved cryptography
to protect classified information in accordance with applicable federal laws,
Executive Orders, directives, policies, regulations, and standards."
  desc  "Use of weak or untested encryption algorithms undermines the purposes
of utilizing encryption to protect data. The Ubuntu operating system must
implement cryptographic modules adhering to the higher standards approved by
the federal government since this provides assurance they have been tested and
validated.


  "
  impact 0.7
  tag "gtitle": "SRG-OS-000396-GPOS-00176"
  tag "satisfies": ["SRG-OS-000396-GPOS-00176", "SRG-OS-000478-GPOS-00223"]
  tag "gid": "V-75503"
  tag "rid": "SV-90183r1_rule"
  tag "stig_id": "UBTU-16-010370"
  tag "fix_id": "F-82131r1_fix"
  tag "cci": ["CCI-002450"]
  tag "nist": ["SC-13", "Rev_4"]
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
  desc "check", "Verify the system is configured to run in FIPS mode.

Check that the system is configured to run in FIPS mode with the following
command:

# grep -i 1 /proc/sys/crypto/fips_enabled
1

If a value of \"1\" is not returned, this is a finding."
  desc "fix", "Configure the system to run in FIPS mode. Add \"fips=1\" to the
kernel parameter during the Ubuntu operating systems install.

Enabling a FIPS mode on a pre-existing system involves a number of
modifications to the Ubuntu operating system. Refer to the Ubuntu Server 16.04
FIPS 140-2 security policy document for instructions."

  config_file = '/proc/sys/crypto/fips_enabled'
  config_file_exists = file(config_file).exist?

  if config_file_exists
    describe parse_config_file(config_file) do
      it { should cmp '1' }
    end
  else
    describe ('FIPS is enabled') do
      subject { config_file_exists }
      it { should be true }
    end
  end
end

