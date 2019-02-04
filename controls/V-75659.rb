control "V-75659" do
  title "The audit event multiplexor must be configured to off-load audit logs
onto a different system or storage media from the system being audited."
  desc  "Information stored in one location is vulnerable to accidental or
incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit
storage capacity.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000479-GPOS-00224"
  tag "gid": "V-75659"
  tag "rid": "SV-90339r2_rule"
  tag "stig_id": "UBTU-16-020210"
  tag "fix_id": "F-82287r2_fix"
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
  desc "check", "Verify the audit event multiplexor is configured to off-load
audit records to a different system or storage media from the system being
audited.

Check that the records are being off-loaded to a remote server with the
following command:

# sudo grep -i active /etc/audisp/plugins.d/au-remote.conf

active = yes

If \"active\" is not set to \"yes\", or the line is commented out, this is a
finding."
  desc "fix", "Configure the audit event multiplexor to off-load audit records
to a different system or storage media from the system being audited.

Set the \"active\" option in \"/etc/audisp/plugins.d/au-remote.conf\" to
\"yes\":

active = yes

In order for the changes to take effect, the audit daemon must be restarted.
The audit daemon can be restarted with the following command:

# sudo systemctl restart auditd.service"
end

