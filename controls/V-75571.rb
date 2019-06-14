exempt_home_users = attribute('exempt_home_users')
non_interactive_shells = attribute('non_interactive_shells')

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
  desc "check", "Verify that all local interactive user initialization files'
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
  desc "fix", "Edit the local interactive user initialization files to change
any PATH variable statements for executables that reference directories other
than their home directory or the system default. If a local interactive user
requires path variables to reference a directory owned by the application, it
must be documented with the Information System Security Officer (ISSO)."

  ignore_shells = non_interactive_shells.join('|')

  findings = Set[]
  users.where{ !shell.match(ignore_shells) && (uid >= 1000 || uid == 0)}.entries.each do |user_info|
    next if exempt_home_users.include?("#{user_info.username}")
    grep_results =  command("grep -i path --exclude=\".bash_history\" #{user_info.home}/.*").stdout.split("\\n")
    grep_results.each do |result|
      result.slice! "PATH="
      # Case when last value in exec search path is :
      if result[-1] == ":" then
        result = result + " "
      end
      result.slice! "$PATH:"
      result.slice! "$PATH\"\n"
      result.gsub! '$HOME', "#{user_info.home}"
      result.gsub! '~', "#{user_info.home}"
      line_arr = result.split(":")
      line_arr.delete_at(0)
      line_arr.each do |line|
        line.slice! "\""
        # Don't run test on line that exports PATH and is not commented out
        if !line.start_with?('export') && !line.start_with?('#') then
          # Case when :: found in exec search path or : found at beginning
          if line.strip.empty? then
            curr_work_dir = command("pwd").stdout.gsub("\n", "")
            if curr_work_dir.start_with?("#{user_info.home}") then
              line = curr_work_dir
            end
          end          
          # This will fail if non-home directory found in path
          if !line.start_with?(user_info.home)
            findings.add(line)
          end
        end
      end
    end
  end
  describe "Initialization files that include executable search paths that include directories outside their home directories" do
    subject { findings.to_a } 
    it { should be_empty }
  end
end

