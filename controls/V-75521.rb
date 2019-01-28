control "V-75521" do
  title "The file integrity tool must be configured to verify extended
attributes."
  desc  "Extended attributes in file systems are used to contain arbitrary data
and file metadata with security implications."
  impact 0.3
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75521"
  tag "rid": "SV-90201r1_rule"
  tag "stig_id": "UBTU-16-010530"
  tag "fix_id": "F-82149r1_fix"
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
  desc "check", "Verify the file integrity tool is configured to verify extended
attributes.

Check to see if Advanced Intrusion Detection Environment (AIDE) is installed
with the following command:

# dpkg -l |grep aide

ii aide 0.16~a2.git20130520-3
ii aide-common 0.16~a2.git20130520-3

If AIDE is not installed, ask the System Administrator how file integrity
checks are performed on the system.

If there is no application installed to perform integrity checks, this is a
finding.

Note: AIDE is highly configurable at install time. These commands assume the
\"aide.conf\" file is under the \"/etc\" directory.

Use the following command to determine if the file is in another location:

# find / -name aide.conf

Check the \"aide.conf\" file to determine if the \"xattrs\" rule has been added
to the rule list being applied to the files and directories selection lists
with the following command:

# egrep \"[+]?xattrs\" /etc/aide/aide.conf

VarFile = OwnerMode+n+l+X+xattrs

If the \"xattrs\" rule is not being used on all selection lines in the
\"/etc/aide.conf\" file, or extended attributes are not being checked by
another file integrity tool, this is a finding."
  tag "fix": "Configure the file integrity tool to check file and directory
extended attributes.

If AIDE is installed, ensure the \"xattrs\" rule is present on all file and
directory selection lists."
end

