# frozen_string_literal: true

control 'V-75897' do
  title "The Trivial File Transfer Protocol (TFTP) server package must not be
installed if not required for operational support."
  desc  "If TFTP is required for operational support (such as the transmission
of router configurations) its use must be documented with the Information
System Security Officer (ISSO), restricted to only authorized personnel, and
have access control rules established."
  impact 0.7
  tag "gtitle": 'SRG-OS-000480-GPOS-00227'
  tag "gid": 'V-75897'
  tag "rid": 'SV-90577r2_rule'
  tag "stig_id": 'UBTU-16-030720'
  tag "fix_id": 'F-82527r1_fix'
  tag "cci": %w[CCI-000318 CCI-000368 CCI-001812 CCI-001813
                CCI-001814]
  tag "nist": ['CM-3 f', 'CM-6 c', 'CM-11 (2)', 'CM-5 (1)', 'CM-5 (1)', 'Rev_4']
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
  desc 'check', "Verify a Trivial File Transfer Protocol (TFTP) server has not
been installed.

Check to see if a TFTP server has been installed with the following command:

# dpkg -l | grep tftpd-hpa
ii tftpd-hpa 5.2+20150808-1Ubuntu1.16.04.1

If TFTP is installed and the requirement for TFTP is not documented with the
Information System Security Officer (ISSO), this is a finding."
  desc 'fix', "Remove the Trivial File Transfer Protocol (TFTP) package from the
system with the following command:

# sudo apt-get remove tftpd-hpa"

  describe package('tftpd-hpa') do
    it { should_not be_installed }
  end
end
