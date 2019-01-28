control "V-75573" do
  title "Local initialization files must not execute world-writable programs."
  desc  "If user start-up files execute world-writable programs, especially in
unprotected directories, they could be maliciously modified to destroy user
files or otherwise compromise the system at the user level. If the system is
compromised at the user level, it is easier to elevate privileges to eventually
compromise the system at the root and network level."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75573"
  tag "rid": "SV-90253r1_rule"
  tag "stig_id": "UBTU-16-010790"
  tag "fix_id": "F-82201r1_fix"
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
  desc "check", "Verify that local initialization files do not execute
world-writable programs.

Check the system for world-writable files with the following command:

# sudo find / -perm -002 -type f -exec ls -ld {} \\; | more

For all files listed, check for their presence in the local initialization
files with the following commands:

Note: The example will be for a system that is configured to create users’ home
directories in the \"/home\" directory.

# grep <file> /home/*/.*

If any local initialization files are found to reference world-writable files,
this is a finding."
  tag "fix": "Set the mode on files being executed by the local initialization
files with the following command:

# chmod 0755 <file>"
end

