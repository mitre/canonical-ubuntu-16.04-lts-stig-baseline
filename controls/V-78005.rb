control "V-78005" do
  title "The system must use a DoD-approved virus scan program."
  desc  "Virus scanning software can be used to protect a system from
penetration from computer viruses and to limit their spread through
intermediate systems.

    The virus scanning software should be configured to perform scans
dynamically on accessed files. If this capability is not available, the system
must be configured to scan, at a minimum, all altered files on the system on a
daily basis.

    If the system processes inbound SMTP mail, the virus scanner must be
configured to scan all received mail.
  "
  impact 0.7
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-78005"
  tag "rid": "SV-92701r1_rule"
  tag "stig_id": "UBTU-16-030900"
  tag "fix_id": "F-84715r1_fix"
  tag "cci": ["CCI-001668"]
  tag "nist": ["SI-3 a", "Rev_4"]
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
  desc "check", "Verify the system is using a DoD-approved virus scan program.


Check for the presence of \"McAfee VirusScan Enterprise for Linux\" with the
following command:


# systemctl status nails

nails - service for McAfee VirusScan Enterprise for Linux

> Loaded: loaded
/opt/NAI/package/McAfeeVSEForLinux/McAfeeVSEForLinux-2.0.2.<build_number>;
enabled)

> Active: active (running) since Mon 2015-09-27 04:11:22 UTC;21 min ago


If the \"nails\" service is not active, check for the presence of \"clamav\" on
the system with the following command:


# systemctl status clamav-daemon.socket

systemctl status clamav-daemon.socket

clamav-daemon.socket - Socket for Clam AntiVirus userspace daemon

Loaded: loaded (/lib/systemd/system/clamav-daemon.socket; enabled)

Active: active (running) since Mon 2015-01-12 09:32:59 UTC; 7min ago


If neither of these applications are loaded and active, ask the System
Administrator if there is an antivirus package installed and active on the
system.


If no antivirus scan program is active on the system, this is a finding."
  desc "fix", "Install an approved DoD antivirus solution on the system."
end

