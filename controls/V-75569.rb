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
  tag "fix": "Set the mode of the local initialization files to \"0740\" with
the following command:

Note: The example will be for the smithj user, who has a home directory of
\"/home/smithj\".

# chmod 0740 /home/smithj/.<INIT_FILE>"
end

