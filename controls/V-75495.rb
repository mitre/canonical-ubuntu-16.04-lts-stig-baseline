# frozen_string_literal: true

control 'V-75495' do
  title 'Unattended or automatic login via the GUI must not be allowed.'
  desc  "Failure to restrict system access to authenticated users negatively
impacts Ubuntu operating system security."
  impact 0.7
  tag "gtitle": 'SRG-OS-000480-GPOS-00229'
  tag "gid": 'V-75495'
  tag "rid": 'SV-90175r2_rule'
  tag "stig_id": 'UBTU-16-010330'
  tag "fix_id": 'F-82123r2_fix'
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
  desc 'check', "Verify that unattended or automatic login via the GUI is
disabled.

Check that unattended or automatic login is disabled with the following command:

# sudo grep -i automaticloginenable /etc/gdm3/custom.conf

AutomaticLoginEnable=false

If the \"AutomaticLoginEnable\" parameter is not set to \"false\", or is
commented out, this is a finding."
  desc 'fix', "Configure the GUI to not allow unattended or automatic login to
the system.

Add or edit the following line in the \"/etc/gdm3/custom.conf\" file directly
below the \"[daemon]\" tag:

AutomaticLoginEnable=false"

  gnome_installed = (package('ubuntu-gnome-desktop').installed? || package('ubuntu-desktop').installed?)

  if gnome_installed
    describe parse_config_file('/etc/gdm3/custom.conf') do
      its('AutomaticLoginEnable') { should cmp 'false' }
    end
  else
    impact 0
    describe 'Not Applicable as GNOME dekstop environment is installed' do
      subject { gnome_installed }
      it { should be false }
    end
  end
end
