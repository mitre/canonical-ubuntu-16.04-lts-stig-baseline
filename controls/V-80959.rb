control "V-80959" do
  title "The auditd service must be running in the Ubuntu operating system."
  desc  "Configuring the Ubuntu operating system to implement organization-wide
security implementation guides and security checklists ensures compliance with
federal standards and establishes a common security baseline across DoD that
reflects the most restrictive security posture consistent with operational
requirements.

    Configuration settings are the set of parameters that can be changed in
hardware, software, or firmware components of the system that affect the
security posture and/or functionality of the system. Security-related
parameters are those parameters impacting the security state of the system,
including the parameters required to satisfy other security control
requirements. Security-related parameters include, for example: registry
settings; account, file, directory permission settings; and settings for
functions, ports, protocols, services, and remote connections.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-80959"
  tag "rid": "SV-95671r1_rule"
  tag "stig_id": "UBTU-16-020010"
  tag "fix_id": "F-87819r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
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
  desc "check", "Verify the audit service is active.

Check that the audit service is active with the following command:

# service auditd status
Active: active (running)

If the service is not active this is a finding."
  desc "fix", "Start the auditd service, and enable the auditd service with the
following commands:

Start the audit service.
# systemctl start auditd.service

Enable auditd in the targets of the system.
# systemctl enable auditd.service"
end

describe service('auditd') do
  it { should be_installed }
  it { should be_enabled }
  it { should be_running }
end