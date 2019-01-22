control "V-75627" do
  title "The System Administrator (SA) and Information System Security Officer
(ISSO) (at a minimum) must be alerted when the audit storage volume is full."
  desc  "It is critical that when the Ubuntu operating system is at risk of
failing to process audit logs as required, it takes action to mitigate the
failure. Audit processing failures include: software/hardware errors; failures
in the audit capturing mechanisms; and audit storage capacity being reached or
exceeded. Responses to audit failure depend upon the nature of the failure mode.

    When availability is an overriding concern, other approved actions in
response to an audit failure are as follows:

    1) If the failure was caused by the lack of audit record storage capacity,
the Ubuntu operating system must continue generating audit records if possible
(automatically restarting the audit service if necessary), overwriting the
oldest audit records in a first-in-first-out manner.

    2) If audit records are sent to a centralized collection server and
communication with this server is lost or the server fails, the Ubuntu
operating system must queue audit records locally until communication is
restored or until the audit records are retrieved manually. Upon restoration of
the connection to the centralized collection server, action should be taken to
synchronize the local audit data with the collection server.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000047-GPOS-00023"
  tag "gid": "V-75627"
  tag "rid": "SV-90307r1_rule"
  tag "stig_id": "UBTU-16-020050"
  tag "fix_id": "F-82255r1_fix"
  tag "cci": ["CCI-000140"]
  tag "nist": ["AU-5 b", "Rev_4"]
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
  tag "check": "Verify that the System Administrator (SA) and Information
System Security Officer (ISSO) (at a minimum) are notified when the audit
storage volume is full.

Check which action the Ubuntu operating system takes when the audit storage
volume is full with the following command:

# sudo grep max_log_file_action /etc/audit/auditd.conf

max_log_file_action=syslog

If the value of the \"max_log_file_action\" option is set to \"ignore\",
\"rotate\", or \"suspend\", or the line is commented out, this is a finding."
  tag "fix": "Configure the Ubuntu operating system to notify the System
Administrator (SA) and Information System Security Officer (ISSO) when the
audit storage volume is full by configuring the \"max_log_file_action\"
parameter in the \"/etc/audit/auditd.conf\" file with the a value of \"syslog\"
or \"keep_logs\":

max_log_file_action=syslog"
end

