control "V-75585" do
  title "Kernel core dumps must be disabled unless needed."
  desc  "Kernel core dumps may contain the full contents of system memory at
the time of the crash. Kernel core dumps may consume a considerable amount of
disk space and may result in denial of service by exhausting the available
space on the target file system partition."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75585"
  tag "rid": "SV-90265r1_rule"
  tag "stig_id": "UBTU-16-010900"
  tag "fix_id": "F-82213r1_fix"
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
  desc "check", "Verify that kernel core dumps are disabled unless needed.

Check the status of the \"kdump\" service with the following command:

# systemctl status kdump.service
Loaded: not-found (Reason: No such file or directory)
Active: inactive (dead)

If the \"kdump\" service is active, ask the System Administrator if the use of
the service is required and documented with the Information System Security
Officer (ISSO).

If the service is active and is not documented, this is a finding."
  desc "fix", "If kernel core dumps are not required, disable the \"kdump\"
service with the following command:

# systemctl disable kdump.service

If kernel core dumps are required, document the need with the Information
System Security Officer (ISSO)."
end

