control "V-75601" do
  title "The /var/log/syslog file must be owned by syslog."
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
  tag "gtitle": "SRG-OS-000206-GPOS-00084"
  tag "gid": "V-75601"
  tag "rid": "SV-90281r2_rule"
  tag "stig_id": "UBTU-16-010980"
  tag "fix_id": "F-82229r1_fix"
  tag "cci": ["CCI-001314"]
  tag "nist": ["SI-11 b", "Rev_4"]
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
  desc "check", "Verify that the /var/log/syslog file is owned by syslog.

Check that the /var/log/syslog file is owned by syslog with the following
command:

# ls -la /var/log/syslog | cut -d' ' -f3

syslog

If \"syslog\" is not returned as a result, this is a finding."
  tag "fix": "Change the owner of the file /var/log/syslog to syslog by running
the following command:

# sudo chown syslog /var/log/syslog"
end

