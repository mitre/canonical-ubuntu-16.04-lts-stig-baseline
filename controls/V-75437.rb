control "V-75437" do
  title "The Ubuntu operating system must enable a user session lock until that
user re-establishes access using established identification and authentication
procedures."
  desc  "A session lock is a temporary action taken when a user stops work and
moves away from the immediate physical vicinity of the information system but
does not want to log out because of the temporary nature of the absence.

    The session lock is implemented at the point where session activity can be
determined.

    Regardless of where the session lock is determined and implemented, once
invoked, the session lock shall remain in place until the user
re-authenticates. No other activity aside from re-authentication shall unlock
the system.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000028-GPOS-00009"
  tag "gid": "V-75437"
  tag "rid": "SV-90117r3_rule"
  tag "stig_id": "UBTU-16-010040"
  tag "fix_id": "F-82065r2_fix"
  tag "cci": ["CCI-000056"]
  tag "nist": ["AC-11 b", "Rev_4"]
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
  desc "check", "Verify the operating system allows a user to lock the current
graphical user interface (GUI) session.

Note: If the Ubuntu operating system does not have GNOME installed, this
requirement is Not Applicable.

Check to see if the Ubuntu operating system allows the user to lock the current
GUI session with the following command:

# gsettings get org.gnome.desktop.lock-enabled

true

If \"lock-enabled\" is not set to \"true\", this is a finding."
  desc "fix", "Configure the Ubuntu operating system so that it allows a user to
lock the current GUI session.

Note: If the Ubuntu operating system does not have GNOME installed, this
requirement is Not Applicable.

Set the \"lock-enabled\" setting in GNOME to allow GUI session locks with the
following command:

Note: The command must be performed from a terminal window inside the graphical
user interface (GUI).

# sudo gsettings set org.gnome.desktop.lock-enabled true"

  gnome_installed = (package('ubuntu-gnome-desktop').installed? || package('ubuntu-desktop').installed?)

  if gnome_installed
    lock_enabled = command('gsettings get org.gnome.desktop.screensaver lock-enabled')
    describe lock_enabled do
      its('stdout') { should cmp 'true' }
    end
  else
    describe "Not Applicable as GNOME dekstop environment is installed" do
      subject { gnome_installed }
      it { should be false }
    end
  end
end

