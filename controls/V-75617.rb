control "V-75617" do
  title "Audit records must contain information to establish what type of
events occurred, the source of events, where events occurred, and the outcome
of events."
  desc  "Without establishing what type of events occurred, the source of
events, where events occurred, and the outcome of events, it would be difficult
to establish, correlate, and investigate the events leading up to an outage or
attack.

    Audit record content that may be necessary to satisfy this requirement
includes, for example, time stamps, source and destination addresses,
user/process identifiers, event descriptions, success/fail indications,
filenames involved, and access control or flow control rules invoked.

    Associating event types with detected events in the Ubuntu operating system
audit logs provides a means of investigating an attack, recognizing resource
utilization or capacity thresholds, or identifying an improperly configured
Ubuntu operating system.


  "
  impact 0.5
  tag "gtitle": "SRG-OS-000037-GPOS-00015"
  tag "satisfies": ["SRG-OS-000037-GPOS-00015", "SRG-OS-000038-GPOS-00016",
"SRG-OS-000039-GPOS-00017", "SRG-OS-000040-GPOS-00018",
"SRG-OS-000041-GPOS-00019", "SRG-OS-000042-GPOS-00021",
"SRG-OS-000051-GPOS-00024", "SRG-OS-000054-GPOS-00025",
"SRG-OS-000122-GPOS-00063", "SRG-OS-000254-GPOS-00095",
"SRG-OS-000255-GPOS-00096", "SRG-OS-000337-GPOS-00129",
"SRG-OS-000348-GPOS-00136", "SRG-OS-000349-GPOS-00137",
"SRG-OS-000350-GPOS-00138", "SRG-OS-000351-GPOS-00139",
"SRG-OS-000352-GPOS-00140", "SRG-OS-000353-GPOS-00141",
"SRG-OS-000354-GPOS-00142", "SRG-OS-000358-GPOS-00145",
"SRG-OS-000365-GPOS-00152", "SRG-OS-000392-GPOS-00172",
"SRG-OS-000475-GPOS-00220"]
  tag "gid": "V-75617"
  tag "rid": "SV-90297r1_rule"
  tag "stig_id": "UBTU-16-020000"
  tag "fix_id": "F-82245r1_fix"
  tag "cci": ["CCI-000130", "CCI-000131", "CCI-000132", "CCI-000133",
"CCI-000134", "CCI-000135", "CCI-000154", "CCI-000158", "CCI-000172",
"CCI-001464", "CCI-001487", "CCI-001814", "CCI-001875", "CCI-001876",
"CCI-001877", "CCI-001878", "CCI-001880", "CCI-001914", "CCI-002884"]
  tag "nist": ["AU-3", "AU-3", "AU-3", "AU-3", "AU-3", "AU-3 (1)", "AU-6 (4)",
"AU-7 (1)", "AU-12 c", "AU-14 (1)", "AU-3", "CM-5 (1)", "AU-7 a", "AU-7 a",
"AU-7 a", "AU-7 a", "AU-7 a", "AU-12 (3)", "MA-4 (1) (a)", "Rev_4"]
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
  tag "check": "Verify the audit service is configured to produce audit
records.

Check that the audit service is installed properly with the following command:

# dpkg -l | grep auditd

If the \"auditd\" package is not installed, this is a finding.

Check that the audit service is properly running and active on the system with
the following command:

# systemctl is-active auditd.service
active

If the command above returns \"inactive\", this is a finding."
  tag "fix": "Configure the audit service to produce audit records containing
the information needed to establish when (date and time) an event occurred.

Install the audit service (if the audit service is not already installed) with
the following command:

# sudo apt-get install auditd

Enable the audit service with the following command:

# sudo systemctl enable auditd.service

Restart the audit service with the following command:

# sudo systemctl restart auditd.service"
end

