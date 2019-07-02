control "V-80957" do
  title "The x86 Ctrl-Alt-Delete key sequence in the Ubuntu operating system
must be disabled if GNOME is installed."
  desc  "A locally logged-on user who presses Ctrl-Alt-Delete, when at the
console, can reboot the system. If accidentally pressed, as could happen in the
case of a mixed OS environment, this can create the risk of short-term loss of
availability of systems due to unintentional reboot. In the GNOME graphical
environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is
reduced because the user will be prompted before any action is taken."
  impact 0.7
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-80957"
  tag "rid": "SV-95669r1_rule"
  tag "stig_id": "UBTU-16-010631"
  tag "fix_id": "F-87833r1_fix"
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
  desc "check", "Verify the Ubuntu operating system is not configured to reboot
the system when Ctrl-Alt-Delete is pressed when using GNOME.

Check that the \"logout\" target is not bound to an action with the following
command:

# grep logout /etc/dconf/db/local.d/*

logout=''

If the \"logout\" key is bound to an action, is commented out, or is missing,
this is a finding."
  desc "fix", "Configure the system to disable the Ctrl-Alt-Delete sequence when
using GNOME by creating or editing the /etc/dconf/db/local.d/00-disable-CAD
file.

Add the setting to disable the Ctrl-Alt-Delete sequence for GNOME:

[org/gnome/settings-daemon/plugins/media-keys]
logout=’’

Then update the dconf settings:

# dconf update"
end

# #first check if GNOME is installed
# only_if('GNOME is not installed') do
#   package('ubuntu-gnome-desktop').installed?
# end

# #if GNOME is installed then verify that ctrl-alt-delete is disabled
# logout_conf = command('find /etc/dconf/db/local.d/ -type f').stdout.strip.split('\n')
# if logout_conf 
#     describe "GNOME conf files do not contain the logout key bound. This is a finding." do
#       # Fail this
#       it { should_not be_empty }
#     end
#   else
#     logout_conf.each do |file|
#       describe parse_config_file(file, options) do
#         its('logout') { should cmp '' }
#       end do
#       end
#     end
#   end
# end