control "V-75441" do
  title "Ubuntu operating system sessions must be automatically logged out
after 15 minutes of inactivity."
  desc  "An Ubuntu operating system needs to be able to identify when a user's
sessions has idled for longer than 15 minutes. The Ubuntu operating system must
logout a users' session after 15 minutes to prevent anyone from gaining access
to the machine while the user is away."
  impact 0.5
  tag "gtitle": "SRG-OS-000029-GPOS-00010"
  tag "gid": "V-75441"
  tag "rid": "SV-90121r2_rule"
  tag "stig_id": "UBTU-16-010060"
  tag "fix_id": "F-82069r2_fix"
  tag "cci": ["CCI-000057"]
  tag "nist": ["AC-11 a", "Rev_4"]
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
  tag "check": "Verify the Ubuntu operating system initiates a session logout
after a \"15\" minutes of inactivity.

Check that the proper auto logout script exists with the following command:

# cat /etc/profile.d/autologout.sh
TMOUT=900
readonly TMOUT
export TMOUT

If the file \"/etc/profile.d/autologout.sh\" does not exist, the timeout values
are commented out, the output from the function call are not the same, this is
a finding."
  tag "fix": "Configure the Ubuntu operating system to initiate a session
logout after a \"15\" minutes of inactivity.

Create a file to contain the system-wide session auto logout script (if it does
not already exist) with the following command:

# sudo touch /etc/profile.d/autologout.sh

Add the following lines to the \"/etc/profile.d/autologout.sh\" script:

TMOUT=900
readonly TMOUT
export TMOUT"
end

