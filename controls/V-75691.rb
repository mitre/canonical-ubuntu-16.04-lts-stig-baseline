control "V-75691" do
  title "Successful/unsuccessful uses of the su command must generate an audit
record."
  desc  "Without establishing what type of events occurred, it would be
difficult to establish, correlate, and investigate the events leading up to an
outage or attack.

    Audit record content that may be necessary to satisfy this requirement
includes, for example, time stamps, source and destination addresses,
user/process identifiers, event descriptions, success/fail indications,
filenames involved, and access control or flow control rules invoked.

    Associating event types with detected events in the Ubuntu operating system
audit logs provides a means of investigating an attack; recognizing resource
utilization or capacity thresholds; or identifying an improperly configured
Ubuntu operating system.


  "
  impact 0.5
  tag "gtitle": "SRG-OS-000037-GPOS-00015"
  tag "satisfies": ["SRG-OS-000037-GPOS-00015", "SRG-OS-000042-GPOS-00020",
"SRG-OS-000062-GPOS-00031", "SRG-OS-000064-GPOS-0003",
"SRG-OS-000392-GPOS-00172", "SRG-OS-000462-GPOS-00206",
"SRG-OS-000471-GPOS-00215"]
  tag "gid": "V-75691"
  tag "rid": "SV-90371r3_rule"
  tag "stig_id": "UBTU-16-020360"
  tag "fix_id": "F-82319r2_fix"
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
  desc "check", "Verify the Ubuntu operating system generates audit records when
successful/unsuccessful attempts to use the \"su\" command occur.

Check for the following system call being audited by performing the following
command to check the file system rules in \"/etc/audit/audit.rules\":

# sudo grep -iw /bin/su /etc/audit/audit.rules

-a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k
privileged-priv_change

If the command does not return a line, or the line is commented out, this is a
finding."
  desc "fix", "Configure the Ubuntu operating system to generate audit records
when successful/unsuccessful attempts to use the \"su\" command occur.

Add or update the following rule in \"/etc/audit/audit.rules\":

-a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k
privileged-priv_change

The audit daemon must be restarted for the changes to take effect. To restart
the audit daemon, run the following command:

# sudo systemctl restart auditd.service"

  @audit_file = '/bin/su'

  audit_lines_exist = !auditd.lines.index{|line| line.include?(@audit_file)}.nil?
  if audit_lines_exist
    describe auditd.file(@audit_file) do
      its('permissions') { should_not cmp [] }
      its('action') { should_not include 'never' }
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
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

