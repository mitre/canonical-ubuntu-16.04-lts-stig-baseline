known_system_mount_points = input('known_system_mount_points')

control "V-75575" do
  title "File systems that contain user home directories must be mounted to
prevent files with the setuid and setguid bit set from being executed."
  desc  "The \"nosuid\" mount option causes the system to not execute setuid
and setgid files with owner privileges. This option must be used for mounting
any file system not containing approved setuid and setguid files. Executing
files from untrusted file systems increases the opportunity for unprivileged
users to attain unauthorized administrative access."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75575"
  tag "rid": "SV-90255r2_rule"
  tag "stig_id": "UBTU-16-010800"
  tag "fix_id": "F-82203r1_fix"
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
  desc "check", "Verify file systems that contain user home directories are
mounted with the \"nosuid\" option.

Note: If a separate file system has not been created for the user home
directories (user home directories are mounted under \"/\"), this is not a
finding as the \"nosuid\" option cannot be used on the \"/\" system.

Find the file system(s) that contain the user home directories with the
following command:

# awk -F: '($3>=1000)&&($1!=\"nobody\"){print $1,$3,$6}' /etc/passwd

smithj:1001: /home/smithj
robinst:1002: /home/robinst

Check the file systems that are mounted at boot time with the following command:

# more /etc/fstab

UUID=a411dc99-f2a1-4c87-9e05-184977be8539 /home ext4
rw,relatime,discard,data=ordered,nosuid 0 2

If a file system found in \"/etc/fstab\" refers to the user home directory file
system and it does not have the \"nosuid\" option set, this is a finding."
  desc "fix", "Configure the \"/etc/fstab\" to use the \"nosuid\" option on file
systems that contain user home directories for interactive users."

  fstab_mount_points = etc_fstab.entries.map(&:mount_point)
  other_mount_points = fstab_mount_points - known_system_mount_points
  # other_mount_points = fstab_mount_points - input('known_system_mount_points')

  if other_mount_points.count > 0
    other_mount_points.each do |mount_point|
      describe mount(mount_point) do
        its('options') { should include 'nosuid' }
      end
    end
  else
    describe "No other mount points found" do
      skip "Separate file system has not been detected for the user home directories"
    end
  end

end

