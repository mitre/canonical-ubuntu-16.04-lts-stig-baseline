control "V-75649" do
  title "The audit log files must be owned by root."
  desc  "Only authorized personnel should be aware of errors and the details of
the errors. Error messages are an indicator of an organization's operational
state or can identify the Ubuntu operating system or platform. Additionally,
Personally Identifiable Information (PII) and operational information must not
be revealed through error messages to unauthorized personnel or their
designated representatives.

    The structure and content of error messages must be carefully considered by
the organization and development team. The extent to which the information
system is able to identify and handle error conditions is guided by
organizational policy and operational requirements.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000206-GPOS-00084"
  tag "gid": "V-75649"
  tag "rid": "SV-90329r2_rule"
  tag "stig_id": "UBTU-16-020160"
  tag "fix_id": "F-82277r2_fix"
  tag "cci": ["CCI-001314"]
  tag "nist": ["SI-11 b", "Rev_4"]
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
  tag "check": "Verify the audit log files are owned by \"root\".

Check where the audit logs are stored on the system using the following command:

# sudo grep log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Using the audit log path from the command above, replace \"[log_path]\" in the
following command:

# sudo ls -la [log_path] | cut -d' ' -f3
root

If the audit logs are not group-owned by \"root\", this is a finding."
  tag "fix": "Change the owner of the audit log file by running the following
command:

Use the following command to get the audit log path:

# sudo grep log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Using the audit log path from the command above, replace \"[log_path]\" in the
following command:

# sudo chown root [log_path]"
end

