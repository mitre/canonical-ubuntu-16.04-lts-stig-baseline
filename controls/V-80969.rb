control "V-80969" do
  title "Successful/unsuccessful uses of the chcon command must generate an
audit record."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000037-GPOS-00015"
  tag "gid": "V-80969"
  tag "rid": "SV-95681r1_rule"
  tag "stig_id": "UBTU-16-020690"
  tag "fix_id": "F-87829r1_fix"
  tag "cci": ["CCI-000130", "CCI-000135", "CCI-000169", "CCI-000172",
"CCI-002884"]
  tag "nist": ["AU-3", "AU-3 (1)", "AU-12 a", "AU-12 c", "MA-4 (1) (a)",
"Rev_4"]
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
  desc "check", "Verify the Ubuntu operating system generates an audit record
when successful/unsuccessful attempts to use the \"chcon\" command occur.

Check that the following calls are being audited by performing the following
command to check the file system rules in \"/etc/audit/audit.rules\":

# sudo grep -w chcon /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F
auid!=4294967295 -k perm_chng

If the command does not return a line, or the line is commented out, this is a
finding."
  desc "fix", "Configure the audit system to generate an audit event for any
successful/unsuccessful use of the \"chcon\" command.

Add or update the following rules in the \"/etc/audit/audit.rules\" file:

-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F
auid!=4294967295 -k perm_chng

The audit daemon must be restarted for the changes to take effect. To restart
the audit daemon, run the following command:

# sudo systemctl restart auditd.service"

  @audit_file = '/usr/bin/chcon'

  audit_lines_exist = !auditd.lines.index{|line| line.include?(@audit_file)}.nil?
  if audit_lines_exist
    describe auditd.file(@audit_file) do
      its('permissions') { should_not cmp [] }
      its('action') { should_not include 'never' }
    end
  
    @perms = auditd.file(@audit_file).permissions
  
    @perms.each do |perm|
      describe perm do
        it { should include 'x' }
      end
    end
  else
    describe ('Audit line(s) for '+ @audit_file + ' exist') do
      subject { audit_lines_exist }
      it { should be true }
    end
  end
end

