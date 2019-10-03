# frozen_string_literal: true

control 'V-80961' do
  title "The Ubuntu operating system must notify the System Administrator (SA)
and Information System Security Officer (ISSO) (at a minimum) when allocated
audit record storage volume reaches 75% of the repository maximum audit record
storage capacity."
  desc  "If security personnel are not notified immediately when storage volume
reaches 75% utilization, they are unable to plan for audit record storage
capacity expansion."
  impact 0.5
  tag "gtitle": 'SRG-OS-000343-GPOS-00134'
  tag "gid": 'V-80961'
  tag "rid": 'SV-95673r1_rule'
  tag "stig_id": 'UBTU-16-020021'
  tag "fix_id": 'F-87821r1_fix'
  tag "cci": ['CCI-001855']
  tag "nist": ['AU-5 (1)', 'Rev_4']
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
  desc 'check', "Verify the Ubuntu operating system notifies the System
Administrator (SA) and Information System Security Officer (ISSO) (at a
minimum) when allocated audit record storage volume reaches 75% of the
repository maximum audit record storage capacity.

Check the system configuration to determine the partition the audit records are
being written to with the following command:

# sudo grep log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Check the size of the partition that audit records are written to (with the
example being \"/var/log/audit/\"):

# df -h /var/log/audit/
1.0G /var/log/audit

If the audit records are not being written to a partition specifically created
for audit records (in this example \"/var/log/audit\" is a separate partition),
determine the amount of space other files in the partition are currently
occupying with the following command:

# du -sh <partition>
1.0G /var

Determine what the threshold is for the system to take action when 75% of the
repository maximum audit record storage capacity is reached:

# grep -i space_left /etc/audit/auditd.conf
space_left = 250

If the value of the \"space_left\" keyword is not set to 25% of the total
partition size, this is a finding."
  desc 'fix', "Configure the operating system to immediately notify the SA and
ISSO (at a minimum) when allocated audit record storage volume reaches 75% of
the repository maximum audit record storage capacity.

Check the system configuration to determine the partition the audit records are
being written to:

# grep log_file /etc/audit/auditd.conf

Determine the size of the partition that audit records are written to (with the
example being \"/var/log/audit/\"):

# df -h /var/log/audit/

Set the value of the \"space_left\" keyword in \"/etc/audit/auditd.conf\" to
25% of the partition size."

  space_left_percent = input('space_left_percent')
  audit_log_path = input('log_file_dir')

  describe filesystem(audit_log_path) do
    its('percent_free') { should be >= space_left_percent }
  end

  partition_threshold_mb = (filesystem(audit_log_path).size_kb / 1024 * 0.25).to_i
  system_alert_configuration_mb = auditd_conf.space_left.to_i

  describe 'The space_left configuration' do
    subject { system_alert_configuration_mb }
    it { should >= partition_threshold_mb }
  end
end
