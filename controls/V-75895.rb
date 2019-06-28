control "V-75895" do
  title "A File Transfer Protocol (FTP) server package must not be installed
unless needed."
  desc  "The FTP service provides an unencrypted remote access that does not
provide for the confidentiality and integrity of user passwords or the remote
session. If a privileged user were to log on using this service, the privileged
user password could be compromised. SSH or other encrypted file transfer
methods must be used in place of this service."
  impact 0.7
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75895"
  tag "rid": "SV-90575r1_rule"
  tag "stig_id": "UBTU-16-030710"
  tag "fix_id": "F-82525r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
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
  desc "check", "Verify a File Transfer Protocol (FTP) server has not been
installed on the system.

Check to see if a FTP server has been installed with the following commands:

# dpkg -l | grep vsftpd
ii vsftpd 3.0.3-3Ubuntu2

If \"vsftpd\" is installed and is not documented with the Information System
Security Officer (ISSO) as an operational requirement, this is a finding."
  desc "fix", "Document the \"vsftpd\" package with the Information System
Security Officer (ISSO) as an operational requirement or remove it from the
system with the following command:

# sudo apt-get remove vsftpd"

  describe package('vsftpd') do
    it { should_not be_installed }
  end
end

