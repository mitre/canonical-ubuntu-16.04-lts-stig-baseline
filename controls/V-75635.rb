# frozen_string_literal: true

control 'V-75635' do
  title "Audit logs must have a mode of 0600 or less permissive to prevent
unauthorized read access."
  desc  "Unauthorized disclosure of audit records can reveal system and
configuration data to attackers, thus compromising its confidentiality.

    Audit information includes all information (e.g., audit records, audit
settings, audit reports) needed to successfully audit Ubuntu operating system
activity.


  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000057-GPOS-00027'
  tag "satisfies": %w[SRG-OS-000057-GPOS-00027 SRG-OS-000058-GPOS-00028
                      SRG-OS-000059-GPOS-00029]
  tag "gid": 'V-75635'
  tag "rid": 'SV-90315r2_rule'
  tag "stig_id": 'UBTU-16-020090'
  tag "fix_id": 'F-82263r1_fix'
  tag "cci": %w[CCI-000162 CCI-000163 CCI-000164]
  tag "nist": %w[AU-9 AU-9 AU-9 Rev_4]
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
  desc 'check', "Verify the audit logs have a mode of \"0600\" or less
permissive.

First determine where the audit logs are stored with the following command:

# sudo grep -iw log_file /etc/audit/auditd.conf

log_file = /var/log/audit/audit.log

Using the location of the audit log file, check if the audit log has a mode of
\"0600\" or less permissive with the following command:

# sudo stat -c \"%a %n\" /var/log/audit/audit.log

600 /var/log/audit/audit.log

If the audit log has a mode more permissive than \"0600\", this is a finding."
  desc 'fix', "Configure the audit log to be protected from unauthorized read
access by setting the correct permissive mode with the following command:

# sudo chmod 0600 [audit_log_file]

Replace \"[audit_log_file]\" to the correct audit log path, by default this
location is \"/var/log/audit/audit.log\"."

  log_file = auditd_conf.log_file

  log_file_exists = !log_file.nil?
  if log_file_exists
    describe file(log_file) do
      it { should_not be_more_permissive_than('0600') }
    end
  else
    describe ('Audit log file ' + log_file + ' exists') do
      subject { log_file_exists }
      it { should be true }
    end
  end
end
