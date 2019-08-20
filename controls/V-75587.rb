control "V-75587" do
  title "A separate file system must be used for user home directories (such as
/home or an equivalent)."
  desc  "The use of separate file systems for different paths can protect the
system from failures resulting from a file system becoming full or failing."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75587"
  tag "rid": "SV-90267r2_rule"
  tag "stig_id": "UBTU-16-010910"
  tag "fix_id": "F-82215r1_fix"
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
  desc "check", "Verify that a separate file system/partition has been created
for non-privileged local interactive user home directories.

Check the home directory assignment for all non-privileged users, users with a
User Identifier (UID) greater than 1000, on the system with the following
command:

# awk -F: '($3>=1000)&&($1!=\"nobody\"){print $1,$3,$6}' /etc/passwd

adamsj 1001  /home/adamsj
jacksonm 1002 /home/jacksonm
smithj  1003 /home/smithj

The output of the command will give the directory/partition that contains the
home directories for the non-privileged users on the system (in this example,
\"/home\") and users’ shell. All accounts with a valid shell (such as
/bin/bash) are considered interactive users.

Check that a file system/partition has been created for the non-privileged
interactive users with the following command:

Note: The partition of \"/home\" is used in the example.

# grep /home /etc/fstab
UUID=333ada18    /home                   ext4    noatime,nobarrier,nodev  1 2

If a separate entry for the file system/partition that contains the
non-privileged interactive users' home directories does not exist, this is a
finding."
  desc "fix", "Migrate the \"/home\" directory onto a separate file
system/partition."

  non_interactive_shells = input('non_interactive_shells')
  exempt_home_users = input('exempt_home_users')
  ignore_shells = non_interactive_shells.join('|')

  users.where{ !shell.match(ignore_shells) && (uid >= 1000)}.entries.each do |user_info|
    next if exempt_home_users.include?("#{user_info.username}")

    home_mount = command(%(df #{user_info.home} --output=target | tail -1)).stdout.strip
    describe user_info.username do
      context 'with mountpoint' do
        context home_mount do
          it { should_not be_empty }
          it { should_not match(%r(^/$)) }
        end
      end
    end
  end
end

