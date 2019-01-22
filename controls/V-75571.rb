control "V-75571" do
  title "All local interactive user initialization files executable search
paths must contain only paths that resolve to the system default or the users
home directory."
  desc  "The executable search path (typically the PATH environment variable)
contains a list of directories for the shell to search to find executables. If
this path includes the current working directory executables in these
directories may be executed instead of system commands. This variable is
formatted as a colon-separated list of directories. If there is an empty entry,
such as a leading or trailing colon or two consecutive colons, this is
interpreted as the current working directory. If deviations from the default
system search path for the local interactive user are required, they must be
documented with the Information System Security Officer (ISSO)."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75571"
  tag "rid": "SV-90251r1_rule"
  tag "stig_id": "UBTU-16-010780"
  tag "fix_id": "F-82199r1_fix"
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
  tag "check": "Verify that all local interactive user initialization files'
executable search path statements do not contain statements that will reference
a working directory other than the users’ home directory or the system default.

Check the executable search path statement for all local interactive user
initialization files in the users' home directory with the following commands:

Note: The example will be for the smithj user, which has a home directory of
\"/home/smithj\".

# grep -i path /home/smithj/.*
/home/smithj/.bash_profile:PATH=$PATH:$HOME/.local/bin:$HOME/bin
/home/smithj/.bash_profile:export PATH

If any local interactive user initialization files have executable search path
statements that include directories outside of their home directory, and the
additional path statements are not documented with the Information System
Security Officer (ISSO) as an operational requirement, this is a finding."
  tag "fix": "Edit the local interactive user initialization files to change
any PATH variable statements for executables that reference directories other
than their home directory or the system default. If a local interactive user
requires path variables to reference a directory owned by the application, it
must be documented with the Information System Security Officer (ISSO)."
end

