control "V-75859" do
  title "The audit system must take appropriate action when the network cannot
be used to off-load audit records."
  desc  "Information stored in one location is vulnerable to accidental or
incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit
storage capacity.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000479-GPOS-00224"
  tag "gid": "V-75859"
  tag "rid": "SV-90539r2_rule"
  tag "stig_id": "UBTU-16-030430"
  tag "fix_id": "F-82489r1_fix"
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
  desc "check", "Verify that the audit system takes appropriate action if the
network cannot be used to off-load audit records.

Check what action will take place if the network connection fails with the
following command:

# sudo grep -iw \"network_failure\" /etc/audisp/audisp-remote.conf

network_failure_action = stop

If the value of the “network_failure_action” option is not \"syslog\",
\"single\", or \"halt\", or the line is commented out, this is a finding."
  desc "fix", "Configure the Ubuntu operating system to take appropriate action
when the network cannot be used to off-load audit records.

Add, edit or uncomment the \"network_failure_action\" option in
\"/etc/audisp/audisp-remote.conf\". Set it to \"syslog\", \"single\" or
\"halt\" like the below example:

network_failure_action = single"

  config_file_exists = file('/etc/audisp/audisp-remote.conf').exist?

  if config_file_exists
    describe parse_config_file('/etc/audisp/audisp-remote.conf') do
      its('network_failure_action.strip') { should match(/^(syslog|single|halt)$/) }
    end
  else
    describe "/etc/audisp/audisp-remote.conf exists" do
      subject { config_file_exists }
      it { should be true }
    end
  end
end

