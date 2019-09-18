# frozen_string_literal: true

control 'V-75801' do
  title 'The rsh-server package must not be installed.'
  desc  "It is detrimental for Ubuntu operating systems to provide, or install
by default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Ubuntu operating systems are capable of providing a wide variety of
functions and services. Some of the functions and services, provided by
default, may not be necessary to support essential organizational operations
(e.g., key missions, functions).

    The rsh-server service provides an unencrypted remote access service that
does not provide for the confidentiality and integrity of user passwords or the
remote session and has very weak authentication.

    If a privileged user were to log on using this service, the privileged user
password could be compromised.
  "
  impact 0.7
  tag "gtitle": 'SRG-OS-000095-GPOS-00049'
  tag "gid": 'V-75801'
  tag "rid": 'SV-90481r2_rule'
  tag "stig_id": 'UBTU-16-030020'
  tag "fix_id": 'F-82431r1_fix'
  tag "cci": ['CCI-000381']
  tag "nist": ['CM-7 a', 'Rev_4']
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
  desc 'check', "Verify that the rsh-server package is not installed on the
Ubuntu operating system.

Check to see if the rsh-server package is installed with the following command:

# sudo apt list rsh-server

If the rsh-server package is installed, this is a finding."
  desc 'fix', "Configure the Ubuntu operating system to disable non-essential
capabilities by removing the rsh-server package from the system with the
following command:

# sudo apt-get remove rsh-server"

  describe package('rsh-server') do
    it { should_not be_installed }
  end
end
