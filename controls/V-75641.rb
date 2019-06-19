control "V-75641" do
  title "Audit logs must be group-owned by root to prevent unauthorized read
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
"SRG-OS-000059-GPOS-00029", "SRG-OS-000206-GPOS-00084"]
  tag "gid": "V-75641"
  tag "rid": "SV-90321r2_rule"
  tag "stig_id": "UBTU-16-020120"
  tag "fix_id": "F-82269r2_fix"
  tag "cci": ["CCI-000162", "CCI-000163", "CCI-000164", "CCI-001314"]
  tag "nist": ["AU-9", "AU-9", "AU-9", "SI-11 b", "Rev_4"]
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
  desc "check", "Verify the audit logs are group-owned by \"root\". First
determine where the audit logs are stored with the following command:

# sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Using the location of the audit log file, determine if the audit log is
group-owned by \"root\" using the following command:

# sudo ls -la /var/log/audit/audit.log
rw------- 2 root root 8096 Jun 26 11:56 /var/log/audit/audit.log

If the audit log is not group-owned by \"root\", this is a finding."
  desc "fix", "Configure the audit log to be protected from unauthorized read
access, by setting the correct group-owner as \"root\" with the following
command:

# sudo chgrp root [audit_log_file]

Replace \"[audit_log_file]\" to the correct audit log path, by default this
location is \"/var/log/audit/audit.log\"."

  log_file_path = auditd_conf.log_file

  describe file(log_file_path) do
    its('group') { should cmp 'root' }
  end
end

