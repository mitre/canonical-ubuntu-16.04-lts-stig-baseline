control "V-75899" do
  title "If the Trivial File Transfer Protocol (TFTP) server is required, the
TFTP daemon must be configured to operate in secure mode."
  desc  "Restricting TFTP to a specific directory prevents remote users from
copying, transferring, or overwriting system files."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75899"
  tag "rid": "SV-90579r1_rule"
  tag "stig_id": "UBTU-16-030730"
  tag "fix_id": "F-82529r1_fix"
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
  tag "check": "Verify the Trivial File Transfer Protocol (TFTP) daemon is
configured to operate in secure mode.

Check to see if a TFTP server has been installed with the following commands:

# dpkg -l | grep tftpd-hpa
ii tftpd-hpa 5.2+20150808-1Ubuntu1.16.04.1
If a TFTP server is not installed, this is Not Applicable.

If a TFTP server is installed, check for the server arguments with the
following command:

# grep TFTP_OPTIONS /etc/default/tftpd-hpa
TFTP_OPTIONS=\"--secure\"

If \"--secure\" is not listed in the TFTP_OPTIONS, this is a finding."
  tag "fix": "Configure the Trivial File Transfer Protocol (TFTP) daemon to
operate in the secure mode by adding the \"--secure\" option to TFTP_OPTIONS in
/etc/default/tftpd-hpa and restart the tftpd daemon."
end

