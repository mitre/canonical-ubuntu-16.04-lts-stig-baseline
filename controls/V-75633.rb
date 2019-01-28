control "V-75633" do
  title "Off-loading audit records to another system must be authenticated."
  desc  "Information stored in one location is vulnerable to accidental or
incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit
storage capacity.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000479-GPOS-00224"
  tag "gid": "V-75633"
  tag "rid": "SV-90313r1_rule"
  tag "stig_id": "UBTU-16-020080"
  tag "fix_id": "F-82261r1_fix"
  tag "cci": ["CCI-001851"]
  tag "nist": ["AU-4 (1)", "Rev_4"]
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
  desc "check", "Verify the audit system authenticates off-loading audit records
to a different system.

Check that the off-loading of audit records to a different system is
authenticated with the following command:

# sudo grep enable /etc/audisp/audisp-remote.conf

enable_krb5 = yes

If “enable_krb5” option is not set to \"yes\" or the line is commented out,
this is a finding."
  tag "fix": "Configure the audit system to authenticate off-loading audit
records to a different system.

Uncomment the \"enable_krb5\" option in \"/etc/audisp/audisp-remote.conf\" and
set it to \"yes\". See the example below.

enable_krb5 = yes"
end

