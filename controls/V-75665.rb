control "V-75665" do
  title "The Ubuntu operating system must generate audit records for all
account creations, modifications, disabling, and termination events that affect
/etc/gshadow."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).


  "
  impact 0.5
  tag "gtitle": "SRG-OS-000037-GPOS-00015"
  tag "satisfies": ["SRG-OS-000037-GPOS-00015", "SRG-OS-000042-GPOS-00020",
"SRG-OS-000062-GPOS-00031", "SRG-OS-000304-GPOS-00121",
"SRG-OS-000392-GPOS-00172", "SRG-OS-000462-GPOS-00206",
"SRG-OS-000470-GPOS-00214", "SRG-OS-000471-GPOS-00215"]
  tag "gid": "V-75665"
  tag "rid": "SV-90345r3_rule"
  tag "stig_id": "UBTU-16-020320"
  tag "fix_id": "F-82293r2_fix"
  tag "cci": ["CCI-000130", "CCI-000135", "CCI-000169", "CCI-000172",
"CCI-002132", "CCI-002884"]
  tag "nist": ["AU-3", "AU-3 (1)", "AU-12 a", "AU-12 c", "AC-2 (4)", "MA-4 (1)
(a)", "Rev_4"]
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
  desc "check", "Verify the Ubuntu operating system generates audit records for
all account creations, modifications, disabling, and termination events that
affect \"/etc/gshadow\".

Check the auditing rules in \"/etc/audit/audit.rules\" with the following
command:

# sudo grep /etc/gshadow /etc/audit/audit.rules

-w /etc/gshadow -p wa -k audit_rules_usergroup_modification

If the command does not return a line, or the line is commented out, this is a
finding."
  desc "fix", "Configure the Ubuntu operating system to generate audit records
for all account creations, modifications, disabling, and termination events
that affect \"/etc/gshadow\".

Add or update the following file system rule to \"/etc/audit/audit.rules\":

-w /etc/gshadow -p wa -k identity

The audit daemon must be restarted for the changes to take effect. To restart
the audit daemon, run the following command:

# sudo systemctl restart auditd.service"

  file_name = '/etc/gshadow'

  @audit_file = inspec.command('find /etc -type f -name "#{file_name}"').stdout.strip

  describe auditd.file(@audit_file) do
    its('permissions') { should_not cmp [] }
    its('action') { should_not include 'never' }
  end if file(@audit_file).exist?

  # Resource creates data structure including all usages of file
  @perms = auditd.file(@audit_file).permissions

  @perms.each do |perm|
    describe perm do
      it { should include 'w' }
      it { should include 'a' }
    end
  end if file(@audit_file).exist?

  describe "The #{file_name} file does not exist" do
    skip "The #{file_name} file does not exist, this requirement is Not Applicable."
  end if !file(@audit_file).exist?
end

