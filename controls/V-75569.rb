exempt_home_users = attribute('exempt_home_users')
non_interactive_shells = attribute('non_interactive_shells')

control "V-75569" do
  title "All local initialization files must have mode 0740 or less permissive."
  desc  "Local initialization files are used to configure the user's shell
environment upon logon. Malicious modification of these files could compromise
accounts upon logon."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75569"
  tag "rid": "SV-90249r1_rule"
  tag "stig_id": "UBTU-16-010770"
  tag "fix_id": "F-82197r1_fix"
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
  desc "check", "Verify that all local initialization files have a mode of
\"0740\" or less permissive.

Check the mode on all local initialization files with the following command:

Note: The example will be for the smithj user, who has a home directory of
\"/home/smithj\".

# ls -al /home/smithj/.* | more
-rwxr-xr-x 1 smithj users 896 Mar 10 2011 .profile
-rwxr-xr-x 1 smithj users 497 Jan 6 2007 .login
-rwxr-xr-x 1 smithj users 886 Jan 6 2007 .something

If any local initialization files have a mode more permissive than \"0740\",
this is a finding."
  desc "fix", "Set the mode of the local initialization files to \"0740\" with
the following command:

Note: The example will be for the smithj user, who has a home directory of
\"/home/smithj\".

# chmod 0740 /home/smithj/.<INIT_FILE>"

  ignore_shells = non_interactive_shells.join('|')

  findings = Set[]
  users.where{ !shell.match(ignore_shells) && (uid >= 1000 || uid == 0)}.entries.each do |user_info|
    dot_files = command("find #{user_info.home} -xdev -maxdepth 1 -name '.*' -type f").stdout.split("\n")
    dot_files.each do |dot_file|
      next if !file(dot_file).more_permissive_than?('0740')
      findings << dot_file
    end
  end
  describe "All local initialization files have a mode of 0740 or less permissive" do
    subject { findings.to_a }
    it { should be_empty }
  end
end

