control "V-75655" do
  title "Audit tools must be owned by root."
  desc  "Protecting audit information also includes identifying and protecting
the tools used to view and manipulate log data. Therefore, protecting audit
tools is necessary to prevent unauthorized operation on audit information.

    Ubuntu operating systems providing tools to interface with audit
information will leverage user permissions and roles identifying the user
accessing the tools and the corresponding rights the user enjoys in order to
make access decisions regarding the access to audit tools.

    Audit tools include, but are not limited to, vendor-provided and open
source audit tools needed to successfully view and manipulate audit information
system activity and records. Audit tools include custom queries and report
generators.


  "
  impact 0.5
  tag "gtitle": "SRG-OS-000256-GPOS-00097"
  tag "satisfies": ["SRG-OS-000256-GPOS-00097", "SRG-OS-000257-GPOS-00098",
"SRG-OS-000258-GPOS-00099"]
  tag "gid": "V-75655"
  tag "rid": "SV-90335r2_rule"
  tag "stig_id": "UBTU-16-020190"
  tag "fix_id": "F-82283r2_fix"
  tag "cci": ["CCI-001493", "CCI-001494", "CCI-001495"]
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
  desc "check", "Verify the audit tools are owned by \"root\" to prevent any
unauthorized access, deletion, or modification.

Check the owner of each audit tool by running the following command:

# ls -la /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace
/sbin/auditd /sbin/audispd /sbin/augenrules
-rwxr-xr-x 1 root root 97128 Jan 18 2016 /sbin/augenrules

If any of the audit tools are not owned by \"root\", this is a finding."
  tag "fix": "Configure the audit tools to be owned by \"root\", by running the
following command:

# sudo chown root [audit_tool]

Replace \"[audit_tool]\" with each audit tool not owned by \"root\"."
end

