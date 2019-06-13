control "V-80965" do
  title "The audit records must be off-loaded onto a different system or
storage media from the system being audited."
  desc  "Information stored in one location is vulnerable to accidental or
incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit
storage capacity.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000342-GPOS-00133"
  tag "gid": "V-80965"
  tag "rid": "SV-95677r1_rule"
  tag "stig_id": "UBTU-16-020220"
  tag "fix_id": "F-87825r1_fix"
  tag "cci": ["CCI-001851"]
  tag "nist": ["AU-4 (1)", "Rev_4"]
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
  desc "check", "Verify the audit system off-loads audit records to a different
system or storage media from the system being audited.

Check that the records are being off-loaded to a remote server with the
following command:

# sudo grep -i remote_server /etc/audisp/audisp-remote.conf

remote_server = 10.0.1.2

If \"remote_server\" is not configured, or the line is commented out, this is a
finding."
  desc "fix", "Configure the audit system to off-load audit records to a
different system or storage media from the system being audited.

Set the \"remote_server\" option in \"/etc/audisp/audisp-remote.conf\" with the
IP address of the log server. See the example below.

remote_server = 10.0.1.2

In order for the changes to take effect, the audit daemon must be restarted.
The audit daemon can be restarted with the following command:

# sudo systemctl restart auditd.service"

  describe parse_config_file('/etc/audisp/audisp-remote.conf') do
    its('remote_server') { should match /./ }
   end
end

