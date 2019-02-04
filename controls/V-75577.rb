control "V-75577" do
  title "File systems that are used with removable media must be mounted to
prevent files with the setuid and setguid bit set from being executed."
  desc  "The \"nosuid\" mount option causes the system to not execute
\"setuid\" and \"setgid\" files with owner privileges. This option must be used
for mounting any file system not containing approved \"setuid\" and \"setguid\"
files. Executing files from untrusted file systems increases the opportunity
for unprivileged users to attain unauthorized administrative access."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75577"
  tag "rid": "SV-90257r3_rule"
  tag "stig_id": "UBTU-16-010810"
  tag "fix_id": "F-82205r1_fix"
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
  desc "check", "Verify file systems that are used for removable media are
mounted with the \"nosuid\" option.

Check the file systems that are mounted at boot time with the following command:

# more /etc/fstab

UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222 /mnt/usbflash vfat
noauto,owner,ro,nosuid 0 0

If a file system found in \"/etc/fstab\" refers to removable media and it does
not have the \"nosuid\" option set, this is a finding."
  desc "fix", "Configure the \"/etc/fstab\" to use the \"nosuid\" option on file
systems that are associated with removable media."
end

