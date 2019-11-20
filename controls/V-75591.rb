# frozen_string_literal: true

control 'V-75591' do
  title "The Ubuntu operating system must use a separate file system for the
system audit data path."
  desc  "The use of separate file systems for different paths can protect the
system from failures resulting from a file system becoming full or failing."
  impact 0.3
  tag "gtitle": 'SRG-OS-000480-GPOS-00227'
  tag "gid": 'V-75591'
  tag "rid": 'SV-90271r1_rule'
  tag "stig_id": 'UBTU-16-010930'
  tag "fix_id": 'F-82219r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
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
  desc 'check', "Verify that a separate file system/partition has been created
for the system audit data path.

Check that a file system/partition has been created for the system audit data
path with the following command:

Note: /var/log/audit is used as the example as it is a common location.

#grep /var/log/audit /etc/fstab
UUID=3645951a /var/log/audit ext4 defaults 1 2

If a separate entry for \"/var/log/audit\" does not exist, ask the System
Administrator if the system audit logs are being written to a different file
system/partition on the system, then grep for that file system/partition.

If a separate file system/partition does not exist for the system audit data
path, this is a finding."
  desc 'fix', 'Migrate the system audit data path onto a separate file system.'

  audit_log_path = input('audit_log_path')

  describe mount(audit_log_path) do
    it { should be_mounted }
  end
end
