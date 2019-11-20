# frozen_string_literal: true

control 'V-75583' do
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
  tag "gtitle": 'SRG-OS-000480-GPOS-00227'
  tag "gid": 'V-75583'
  tag "rid": 'SV-90263r2_rule'
  tag "stig_id": 'UBTU-16-010840'
  tag "fix_id": 'F-82211r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
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
  desc 'check', "Verify all world-writable directories are group-owned by root,
sys, bin, or an application group.

Check the system for world-writable directories with the following command:

#  sudo find / -perm -2 -type d ! -group sys ! -group root ! -group bin -exec
ls -lLd {} \\;
drwxrwsrwt 2 root whoops 4096 Jun  6 07:44 /var/crash
drwxrwsrwt 2 root whoops 4096 Jul 19  2016 /var/metrics

If any world-writable directories are not owned by root, sys, bin, or an
application group associated with the directory, this is a finding."
  desc 'fix', "Change the group of the world-writable directories to root with
the following command:

# chgrp root <directory>"

  application_groups = input('application_groups')

  directories = command('find / -xdev -perm -2 -type d ! -group sys ! -group root ! -group bin -exec ls -lLd {} \\;').stdout.strip.split("\n").entries
  if directories.count > 0
    directories.each do |entry|
      describe directory(entry) do
        its('group') { should be_in %w[root sys bin] + application_groups }
      end
    end
  else
    describe 'No world-writable directories found on the system' do
      subject { directories }
      its('count') { should eq 0 }
    end
  end
end
