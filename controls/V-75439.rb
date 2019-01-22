control "V-75439" do
  title "All users must be able to directly initiate a session lock for all
connection types."
  desc  "A session lock is a temporary action taken when a user stops work and
moves away from the immediate physical vicinity of the information system but
does not want to log out because of the temporary nature of the absence.

    The session lock is implemented at the point where session activity can be
determined. Rather than be forced to wait for a period of time to expire before
the user session can be locked, Ubuntu operating systems need to provide users
with the ability to manually invoke a session lock so users may secure their
session should the need arise for them to temporarily vacate the immediate
physical vicinity.


  "
  impact 0.5
  tag "gtitle": "SRG-OS-000028-GPOS-00009"
  tag "satisfies": ["SRG-OS-000028-GPOS-00009", "SRG-OS-000030-GPOS-00011",
"SRG-OS-000031-GPOS-00012"]
  tag "gid": "V-75439"
  tag "rid": "SV-90119r2_rule"
  tag "stig_id": "UBTU-16-010050"
  tag "fix_id": "F-82067r1_fix"
  tag "cci": ["CCI-000056", "CCI-000058", "CCI-000060"]
  tag "nist": ["AC-11 b", "AC-11 a", "AC-11 (1)", "Rev_4"]
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
  tag "check": "Verify the Ubuntu operating system has the 'vlock' package
installed, by running the following command:

# dpkg -l | grep vlock

vlock_2.2.2-7

If \"vlock\" is not installed, this is a finding."
  tag "fix": "Install the \"vlock\" (if it is not already installed) package by
running the following command:

# sudo apt-get install vlock"
end

