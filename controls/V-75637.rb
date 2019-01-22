control "V-75637" do
  title "Audit log directories must have a mode of 0750 or less permissive to
prevent unauthorized read access."
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
  tag "gid": "V-75637"
  tag "rid": "SV-90317r2_rule"
  tag "stig_id": "UBTU-16-020100"
  tag "fix_id": "F-82265r1_fix"
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
  tag "check": "Verify the audit log directories have a mode of \"0750\" or
less permissive by first determining where the audit logs are stored with the
following command:

# sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Using the location of the audit log, determine the directory where the audit
logs are stored (ex: \"/var/log/audit\"). Run the following command to
determine the permissions for the audit log folder:

# sudo stat -c \"%a %n\" /var/log/audit
750 /var/log/audit

If the audit log directory has a mode more permissive than \"0750\", this is a
finding."
  tag "fix": "Configure the audit log directory to be protected from
unauthorized read access by setting the correct permissive mode with the
following command:

# sudo chmod 0750 [audit_log_directory]

Replace \"[audit_log_directory]\" to the correct audit log directory path, by
default this location is \"/var/log/audit\"."
end

