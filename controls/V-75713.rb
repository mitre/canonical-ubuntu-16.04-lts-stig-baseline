control "V-75713" do
  title "The audit system must be configured to audit any usage of the modprobe
command."
  desc  "Without the capability to generate audit records, it would be
difficult to establish, correlate, and investigate the events relating to an
incident or identify those responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).

    The list of audited events is the set of events for which audits are to be
generated. This set of events is typically a subset of the list of all events
for which the system is capable of generating audit records.

    DoD has defined the list of events for which the Ubuntu operating system
will provide an audit record generation capability as the following:

    1) Successful and unsuccessful attempts to access, modify, or delete
privileges, security objects, security levels, or categories of information
(e.g., classification levels);

    2) Access actions, such as successful and unsuccessful logon attempts,
privileged activities or other system-level access, starting and ending time
for user access to the system, concurrent logons from different workstations,
successful and unsuccessful accesses to objects, all program initiations, and
all direct access to the information system;

    3) All account creations, modifications, disabling, and terminations; and

    4) All kernel module load, unload, and restart actions.


  "
  impact 0.5
  tag "gtitle": "SRG-OS-000037-GPOS-00015"
  tag "satisfies": ["SRG-OS-000037-GPOS-00015", "SRG-OS-000042-GPOS-00020",
"SRG-OS-000062-GPOS-00031", "SRG-OS-000392-GPOS-00172",
"SRG-OS-000462-GPOS-00206", "SRG-OS-000471-GPOS-00215"]
  tag "gid": "V-75713"
  tag "rid": "SV-90393r2_rule"
  tag "stig_id": "UBTU-16-020440"
  tag "fix_id": "F-82341r2_fix"
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
  desc "check", "Verify if the Ubuntu operating system is configured to audit
the execution of the module management program \"modprobe\", by running the
following command:

# sudo grep \"/sbin/modprobe\" /etc/audit/audit.rules

-w /sbin/modprobe -p x -k modules

If the command does not return a line, or the line is commented out, this is a
finding."
  desc "fix", "Configure the Ubuntu operating system to audit the execution of
the module management program \"modprobe\", by adding the following line to
\"/etc/audit/audit.rules\":

-w /sbin/modprobe -p x -k modules

The audit daemon must be restarted for the changes to take effect. To restart
the audit daemon, run the following command:

# sudo systemctl restart auditd.service"

  @audit_file = '/sbin/modprobe'

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

