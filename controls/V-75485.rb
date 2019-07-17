control "V-75485" do
  title "Account identifiers (individuals, groups, roles, and devices) must
disabled after 35 days of inactivity."
  desc  "Inactive identifiers pose a risk to systems and applications because
attackers may exploit an inactive identifier and potentially obtain undetected
access to the system. Owners of inactive accounts will not notice if
unauthorized access to their user account has been obtained.

    Ubuntu operating systems need to track periods of inactivity and disable
application identifiers after 35 days of inactivity.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000118-GPOS-00060"
  tag "gid": "V-75485"
  tag "rid": "SV-90165r3_rule"
  tag "stig_id": "UBTU-16-010280"
  tag "fix_id": "F-82113r1_fix"
  tag "cci": ["CCI-000795"]
  tag "nist": ["IA-4 e", "Rev_4"]
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
  desc "check", "Verify the account identifiers (individuals, groups, roles, and
devices) are disabled after \"35\" days of inactivity with the following
command:

Check the account inactivity value by performing the following command:

# sudo grep -i inactive /etc/default/useradd

INACTIVE=35

If \"INACTIVE\" is not set to a value \"0<[VALUE]<=35\", or is commented out,
this is a finding."
  desc "fix", "Configure the Ubuntu operating system to disable account
identifiers after 35 days of inactivity after the password expiration.

Run the following command to change the configuration for useradd:

# sudo useradd -D -f 35

DoD recommendation is 35 days, but a lower value is acceptable. The value
\"-1\" will disable this feature, and \"0\" will disable the account
immediately after the password expires."

  config_file = '/etc/default/useradd'
  config_file_exists = file(config_file).exist?

  if config_file_exists
    describe parse_config_file(config_file) do
      its('INACTIVE') { should cmp > '0' }
      its('INACTIVE') { should cmp <= '35' }
    end
  else
    describe (config_file + ' exists') do
      subject { config_file_exists }
      it { should be true }
    end
  end
end

