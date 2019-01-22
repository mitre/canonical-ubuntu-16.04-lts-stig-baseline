control "V-75697" do
  title "Successful/unsuccessful uses of the umount command must generate an
audit record."
  desc  "Reconstruction of harmful events or forensic analysis is not possible
if audit records do not contain enough information.

    At a minimum, the organization must audit the full-text recording of
privileged commands. The organization must maintain audit trails in sufficient
detail to reconstruct events to determine the cause and impact of compromise.


  "
  impact 0.5
  tag "gtitle": "SRG-OS-000042-GPOS-00020"
  tag "satisfies": ["SRG-OS-000042-GPOS-00020", "SRG-OS-000392-GPOS-00172",
"SRG-OS-000471-GPOS-00215"]
  tag "gid": "V-75697"
  tag "rid": "SV-90377r3_rule"
  tag "stig_id": "UBTU-16-020390"
  tag "fix_id": "F-82325r2_fix"
  tag "cci": ["CCI-000135", "CCI-000172", "CCI-002884"]
  tag "nist": ["AU-3 (1)", "AU-12 c", "MA-4 (1) (a)", "Rev_4"]
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
  tag "check": "Verify that an audit event is generated for any
successful/unsuccessful use of the \"umount\" command.

Check for the following system call being audited by performing the following
command to check the file system rules in \"/etc/audit/audit.rules\":

# sudo grep umount /etc/audit/audit.rules

-a always,exit -F path=/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295
-k privileged-mount

If the command does not return a line, or the line is commented out, this is a
finding."
  tag "fix": "Configure the audit system to generate an audit event for any
successful/unsuccessful use of the \"umount\" command.

Add or update the following rules in the \"/etc/audit/audit.rules\" file:

-a always,exit -F path=/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295
-k privileged-mount

The audit daemon must be restarted for the changes to take effect. To restart
the audit daemon, run the following command:

# sudo systemctl restart auditd.service"
end

