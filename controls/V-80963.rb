# frozen_string_literal: true

control 'V-80963' do
  title "The audit log files in the Ubuntu operating system must have mode 0640
or less permissive."
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
  tag "gtitle": 'SRG-OS-000206-GPOS-00084'
  tag "gid": 'V-80963'
  tag "rid": 'SV-95675r1_rule'
  tag "stig_id": 'UBTU-16-020170'
  tag "fix_id": 'F-87823r1_fix'
  tag "cci": ['CCI-001314']
  tag "nist": ['SI-11 b', 'Rev_4']
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
  desc 'check', "Verify that the audit log files have a mode of \"0640\" or less
permissive.

Check where the audit logs are stored on the system using the following command:

# sudo grep log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Using the audit log path from the command above, replace \"[log_path]\" in the
following command:

# sudo ls -lad [log_file] | cut -d' ' -f1
ls -lad /var/log/audit/audit.log | cut -d' ' -f1
-rw-r-----

If the audit log file does not have a mode of \"0640\" or less permissive, this
is a finding."
  desc 'fix', "Configure the octal permission value of the audit log to \"0640\"
or less permissive.

Use the following command to find where the audit log files are stored on the
system:

# sudo grep log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Using the audit log path from the command above, replace \"[log_path]\" in the
following command:

# sudo chmod 0640 [log_path]"

  log_file_path = auditd_conf.log_file
  if log_file_path.nil?
    describe "auditd.conf's log_file specification" do
      subject { log_file_path }
      it { should_not be_nil }
    end
  else
    describe file(log_file_path) do
      it { should exist }
      it { should_not be_more_permissive_than('0640') }
    end
  end
end
