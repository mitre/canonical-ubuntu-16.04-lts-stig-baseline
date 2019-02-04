control "V-75643" do
  title "Audit log directory must be owned by root to prevent unauthorized read
access."
  desc  "Unauthorized disclosure of audit records can reveal system and
configuration data to attackers, thus compromising its confidentiality.

    Audit information includes all information (e.g., audit records, audit
settings, audit reports) needed to successfully audit Ubuntu operating system
activity.


  "
  impact 0.5
  tag "gtitle": "SRG-OS-000057-GPOS-00027"
  tag "satisfies": ["SRG-OS-000057-GPOS-00027", "SRG-OS-000058-GPOS-00028",
"SRG-OS-000059-GPOS-00029"]
  tag "gid": "V-75643"
  tag "rid": "SV-90323r2_rule"
  tag "stig_id": "UBTU-16-020130"
  tag "fix_id": "F-82271r2_fix"
  tag "cci": ["CCI-000162", "CCI-000163", "CCI-000164"]
  tag "nist": ["AU-9", "AU-9", "AU-9", "Rev_4"]
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
  desc "check", "Verify the audit log directory is owned by \"root\" to prevent
unauthorized read access.

Determine where the audit logs are stored with the following command:

# sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Determine the audit log directory by using the output of the above command (ex:
\"/var/log/audit/\"). Run the following command with the correct audit log
directory path:

# sudo ls -ld /var/log/audit
drwxr-x--- 2 root root 8096 Jun 26 11:56 /var/log/audit

If the audit log directory is not owned by \"root\", this is a finding."
  desc "fix", "Configure the audit log to be protected from unauthorized read
access, by setting the correct owner as \"root\" with the following command:

# sudo chown root [audit_log_directory]

Replace \"[audit_log_directory]\" with the correct audit log directory path, by
default this location is usually \"/var/log/audit\"."
end

