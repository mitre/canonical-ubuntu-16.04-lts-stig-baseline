control "V-75523" do
  title "The file integrity tool must notify the system administrator when
changes to the baseline configuration or anomalies in the operation of any
security functions are discovered."
  desc  "Unauthorized changes to the baseline configuration could make the
system vulnerable to various attacks or allow unauthorized access to the Ubuntu
operating system. Changes to Ubuntu operating system configurations can have
unintended side effects, some of which may be relevant to security.

    Security function is defined as the hardware, software, and/or firmware of
the information system responsible for enforcing the system security policy and
supporting the isolation of code and data on which the protection is based.
Security functionality includes, but is not limited to, establishing system
accounts, configuring access authorizations (i.e., permissions, privileges),
setting events to be audited, and setting intrusion detection parameters.

    Detecting such changes and providing an automated response can help avoid
unintended, negative consequences that could ultimately affect the security
state of the Ubuntu operating system. The Ubuntu operating system's IMO/ISSO
and SAs must be notified via email and/or monitoring system trap when there is
an unauthorized modification of a configuration item.

    Notifications provided by information systems include messages to local
computer consoles, and/or hardware indications, such as lights.

    This capability must take into account operational requirements for
availability for selecting an appropriate response. The organization may choose
to shut down or restart the information system upon security function anomaly
detection.


  "
  impact 0.5
  tag "gtitle": "SRG-OS-000363-GPOS-00150"
  tag "satisfies": ["SRG-OS-000363-GPOS-00150", "SRG-OS-000447-GPOS-00201"]
  tag "gid": "V-75523"
  tag "rid": "SV-90203r3_rule"
  tag "stig_id": "UBTU-16-010540"
  tag "fix_id": "F-82151r2_fix"
  tag "cci": ["CCI-001744", "CCI-002702"]
  tag "nist": ["CM-3 (5)", "SI-6 d", "Rev_4"]
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
  desc "check", "Verify that Advanced Intrusion Detection Environment (AIDE)
notifies the system administrator when anomalies in the operation of any
security functions are discovered.

Check that AIDE notifies the system administrator when anomalies in the
operation of any security functions are discovered with the following command:

# sudo grep SILENTREPORTS /etc/default/aide

SILENTREPORTS=no

If the \"/etc/cron.daily/aide\" file does not exist, the cron job is configured
with the \"SILENTREPORTS=yes\" option, or the line is commented out, this is a
finding."
  tag "fix": "Modify the \"SILENTREPORTS\" parameter in \"/etc/default/aide\"
file with a value \"no\" of if it does not already exist:

SILENTREPORTS=no
"
end

