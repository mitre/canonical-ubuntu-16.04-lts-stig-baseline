control "V-75529" do
  title "Advance package Tool (APT) must remove all software components after
updated versions have been installed."
  desc  "Previous versions of software components that are not removed from the
information system after updates have been installed may be exploited by
adversaries. Some information technology products may remove older versions of
software automatically from the information system."
  impact 0.5
  tag "gtitle": "SRG-OS-000437-GPOS-00194"
  tag "gid": "V-75529"
  tag "rid": "SV-90209r1_rule"
  tag "stig_id": "UBTU-16-010570"
  tag "fix_id": "F-82157r1_fix"
  tag "cci": ["CCI-002617"]
  tag "nist": ["SI-2 (6)", "Rev_4"]
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
  desc "check", "Verify Advance package Tool (APT) is configured to remove all
software components after updated versions have been installed.

Check that APT is configured to remove all software components after updating
with the following command:

# grep -i remove-unused /etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Remove-Unused-Dependencies \"true\";

If the \"Remove-Unused-Dependencies\" parameter is not set to \"true\", or is
missing, this is a finding."
  desc "fix", "Configure APT to remove all software components after updated
versions have been installed.

Add or updated the following option to the
\"/etc/apt/apt.conf.d/50unattended-upgrades\" file:

Unattended-Upgrade::Remove-Unused-Dependencies \"true\";"
end

