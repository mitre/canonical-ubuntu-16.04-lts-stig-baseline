control "V-75513" do
  title "All world-writable directories must be group-owned by root, sys, bin,
or an application group."
  desc  "If a world-writable directory has the sticky bit set and is not
group-owned by a privileged Group Identifier (GID), unauthorized users may be
able to modify files created by others.

    The only authorized public directories are those temporary directories
supplied with the system or those designed to be temporary file repositories.
The setting is normally reserved for directories used by the system and by
users for temporary file storage, (e.g., /tmp), and for directories requiring
global read/write access.

  "
  impact 0.5
  tag "gtitle": "SRG-OS-000138-GPOS-00069"
  tag "gid": "V-75513"
  tag "rid": "SV-90193r3_rule"
  tag "stig_id": "UBTU-16-010420"
  tag "fix_id": "F-82141r2_fix"
  tag "cci": ["CCI-001090"]
  tag "nist": ["SC-4", "Rev_4"]
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
  desc "check", "Verify that all world-writable directories are group-owned by
root to prevent unauthorized and unintended information transferred via shared
system resources.

Check the system for world-writable directories with the following command:

# sudo find / -type d -perm -0002 -exec ls -lLd {} \\;

drwxrwxrwxt 7 root root 4096 Jul 26 11:19 /tmp

If any world-writable directories are not owned by root, sys, bin, or an
application group associated with the directory, this is a finding."
  desc "fix", "Change the group of the world-writable directories to root, sys,
bin, or an application group with the following command, replacing
\"[world-writable Directory]\":

# sudo chgrp root [world-writable Directory]"

  application_groups = input('application_groups')

  directories = command("sudo find / -type d -perm -0002 -exec ls -Ld {} \\;").stdout.strip.split("\n").entries
  if directories.count > 0
    directories.each do |entry|
      describe directory(entry) do
        its('group') { should be_in ['root','sys', 'bin'] + application_groups}
      end
    end
  else
    describe "No world-writable directories found" do
      skip "No world-writable directories found on the system"
    end
  end
end

