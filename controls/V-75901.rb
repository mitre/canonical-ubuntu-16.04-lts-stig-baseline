control "V-75901" do
  title "An X Windows display manager must not be installed unless approved."
  desc  "Internet services that are not required for system or application
processes must not be active to decrease the attack surface of the system. X
Windows has a long history of security vulnerabilities and will not be used
unless approved and documented."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75901"
  tag "rid": "SV-90581r1_rule"
  tag "stig_id": "UBTU-16-030740"
  tag "fix_id": "F-82531r1_fix"
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
  tag "check": "Verify that if X Windows is installed it is authorized.

Check for the X11 package with the following command:

# dpkg -l | grep lightdm

Ask the System Administrator if use of the X Windows system is an operational
requirement.

If the use of X Windows on the system is not documented with the Information
System Security Officer (ISSO), this is a finding."
  tag "fix": "Document the requirement for an X Windows server with the
Information System Security Officer (ISSO) or remove the related packages with
the following commands:

# sudo apt-get purge lightdm"
end

