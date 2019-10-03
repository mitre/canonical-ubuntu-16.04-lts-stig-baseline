# frozen_string_literal: true

control 'V-75631' do
  title "The audit system must take appropriate action when audit storage is
full."
  desc  "Information stored in one location is vulnerable to accidental or
incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit
storage capacity.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000479-GPOS-00224'
  tag "gid": 'V-75631'
  tag "rid": 'SV-90311r1_rule'
  tag "stig_id": 'UBTU-16-020070'
  tag "fix_id": 'F-82259r1_fix'
  tag "cci": ['CCI-001851']
  tag "nist": ['AU-4 (1)', 'Rev_4']
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
  desc 'check', "Verify the action that the audit system takes when the storage
volume becomes full.

Check the action that the audit system takes when the storage volume becomes
full with the following command:

# sudo grep disk_full /etc/audisp/audisp-remote.conf

disk_full_action = single

If the value of the \"disk_full_action\" option is not \"syslog\", \"single\",
or \"halt\", or the line is commented out, this is a finding."
  desc 'fix', "Configure the audit system to take an appropriate action when the
audit storage is full.

Add, edit or uncomment the \"disk_full_action\" option in
\"/etc/audisp/audisp-remote.conf\". Set it to \"syslog\", \"single\" or
\"halt\" like the below example:

disk_full_action = single"

  config_file_exists = file('/etc/audisp/audisp-remote.conf').exist?

  if config_file_exists
    describe auditd_conf('/etc/audisp/audisp-remote.conf') do
      its('disk_full_action') { should_not be_empty }
      its('disk_full_action') { should cmp /(?:SYSLOG|SINGLE|HALT)/i }
    end
  else
    describe '/etc/audisp/audisp-remote.conf exists' do
      subject { config_file_exists }
      it { should be true }
    end
  end
end
